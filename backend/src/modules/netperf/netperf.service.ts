/**
 * NPM ligero: rendimiento de red por interfaz del FortiGate.
 * Sondea la API de interfaces cada N segundos y calcula, a partir de los deltas
 * de los contadores de bytes, el throughput (bps) y la % de utilización frente a
 * la velocidad del enlace. Guarda una muestra por interfaz en `iface_samples`
 * (serie para el reporte) y mantiene una ventana en memoria para el panel en vivo.
 *
 * Estabilidad = link up/down + errores; velocidad = capacidad del enlace;
 * rendimiento = throughput y % de utilización. Fuente única: FortiGate.
 */
import { fetchInterfaces, isFortigateConfigured, type FgInterface } from '../response/fortigate.service';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

const POLL_SECONDS = Number(process.env.NETPERF_POLL_SECONDS || 60);
const RETAIN_DAYS = Number(process.env.NETPERF_RETAIN_DAYS || 30);
const WINDOW = 120; // muestras en memoria por interfaz (~2 h a 60 s)

export interface IfaceSample { ts: number; inBps: number; outBps: number; utilPct: number }
interface IfaceState {
  name: string; alias: string | null; ip: string | null;
  link: boolean; speedMbps: number; txErrors: number; rxErrors: number;
  inBps: number; outBps: number; utilPct: number; peakUtilPct: number; flaps: number;
  samples: IfaceSample[];
  _lastTx: number; _lastRx: number; _lastTs: number; _lastLink: boolean;
}

const state = new Map<string, IfaceState>();
let lastPollAt = 0;
let lastPollOk = false;

function util(inBps: number, outBps: number, speedMbps: number): number {
  if (speedMbps <= 0) return 0;
  const cap = speedMbps * 1_000_000; // bits/s
  return Math.min(100, Math.round((Math.max(inBps, outBps) / cap) * 1000) / 10);
}

async function pollOnce(): Promise<void> {
  let ifaces: FgInterface[];
  try {
    ifaces = await fetchInterfaces();
  } catch (err) {
    lastPollOk = false;
    logger.warn({ err: err instanceof Error ? err.message : err }, 'netperf: fallo al leer interfaces');
    return;
  }
  const now = Date.now();
  const toPersist: [string, number, number, number, boolean][] = [];
  for (const i of ifaces) {
    let s = state.get(i.name);
    if (!s) {
      s = {
        name: i.name, alias: i.alias, ip: i.ip, link: i.link, speedMbps: i.speedMbps,
        txErrors: i.txErrors, rxErrors: i.rxErrors, inBps: 0, outBps: 0, utilPct: 0, peakUtilPct: 0, flaps: 0,
        samples: [], _lastTx: i.txBytes, _lastRx: i.rxBytes, _lastTs: now, _lastLink: i.link,
      };
      state.set(i.name, s);
      continue; // primera lectura = línea base, sin delta todavía
    }
    const dt = (now - s._lastTs) / 1000;
    // deltas de contadores; ignora reinicios (delta negativo) o dt inválido
    const dTx = i.txBytes - s._lastTx;
    const dRx = i.rxBytes - s._lastRx;
    const outBps = dt > 0 && dTx >= 0 ? Math.round((dTx * 8) / dt) : 0;
    const inBps = dt > 0 && dRx >= 0 ? Math.round((dRx * 8) / dt) : 0;
    const u = util(inBps, outBps, i.speedMbps);
    if (s._lastLink !== i.link) s.flaps++;
    s.alias = i.alias; s.ip = i.ip; s.link = i.link; s.speedMbps = i.speedMbps;
    s.txErrors = i.txErrors; s.rxErrors = i.rxErrors;
    s.inBps = inBps; s.outBps = outBps; s.utilPct = u;
    s.peakUtilPct = Math.max(s.peakUtilPct, u);
    s.samples.push({ ts: now, inBps, outBps, utilPct: u });
    if (s.samples.length > WINDOW) s.samples.shift();
    s._lastTx = i.txBytes; s._lastRx = i.rxBytes; s._lastTs = now; s._lastLink = i.link;
    toPersist.push([i.name, inBps, outBps, u, i.link]);
  }
  lastPollAt = now; lastPollOk = true;

  if (toPersist.length) {
    try {
      const vals: unknown[] = [];
      const rows = toPersist.map((t, k) => {
        const b = k * 5;
        vals.push(t[0], t[1], t[2], t[3], t[4]);
        return `(now(), $${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5})`;
      });
      await query(`INSERT INTO iface_samples (ts, iface, in_bps, out_bps, util_pct, link) VALUES ${rows.join(',')}`, vals);
    } catch (err) {
      logger.warn({ err: err instanceof Error ? err.message : err }, 'netperf: fallo al persistir muestra');
    }
  }
}

let pruneCounter = 0;
async function prune(): Promise<void> {
  // Cada ~1h (60 ciclos de 60 s) borra muestras viejas.
  if (++pruneCounter % 60 !== 0) return;
  await query(`DELETE FROM iface_samples WHERE ts < now() - ($1 || ' days')::interval`, [String(RETAIN_DAYS)]).catch(() => undefined);
}

export function startNetperfPoller(): void {
  if (!isFortigateConfigured()) {
    logger.info('netperf: FortiGate no configurado; el sondeo de interfaces no arranca.');
    return;
  }
  const tick = () => void pollOnce().then(prune).catch(() => undefined);
  void tick();
  setInterval(tick, POLL_SECONDS * 1000);
  logger.info({ POLL_SECONDS }, 'netperf: sondeo de interfaces del FortiGate iniciado');
}

/** Estado en vivo por interfaz (para el panel). */
export function getInterfacesLive(): {
  polling: boolean; lastPollAt: number | null; pollSeconds: number;
  interfaces: {
    name: string; alias: string | null; ip: string | null; link: boolean; speedMbps: number;
    inBps: number; outBps: number; utilPct: number; peakUtilPct: number; flaps: number;
    txErrors: number; rxErrors: number; spark: number[];
  }[];
} {
  const interfaces = [...state.values()]
    .sort((a, b) => b.utilPct - a.utilPct)
    .map((s) => ({
      name: s.name, alias: s.alias, ip: s.ip, link: s.link, speedMbps: s.speedMbps,
      inBps: s.inBps, outBps: s.outBps, utilPct: s.utilPct, peakUtilPct: s.peakUtilPct, flaps: s.flaps,
      txErrors: s.txErrors, rxErrors: s.rxErrors, spark: s.samples.map((x) => x.utilPct),
    }));
  return { polling: lastPollOk, lastPollAt: lastPollAt || null, pollSeconds: POLL_SECONDS, interfaces };
}

export interface IfacePeriodStat {
  iface: string;
  muestras: number;
  utilProm: number; utilPico: number;
  inPromBps: number; outPromBps: number; inPicoBps: number; outPicoBps: number;
  disponibilidadPct: number; // % de muestras con link up
}

/** Estadísticas por interfaz para el periodo del reporte (desde iface_samples). */
export async function getInterfacePeriod(gteIso: string, ltIso: string): Promise<IfacePeriodStat[]> {
  const rows = await query<{
    iface: string; n: string; up: string;
    util_avg: string | null; util_max: string | null;
    in_avg: string | null; out_avg: string | null; in_max: string | null; out_max: string | null;
  }>(
    `SELECT iface,
            count(*) n,
            count(*) FILTER (WHERE link) up,
            avg(util_pct) util_avg, max(util_pct) util_max,
            avg(in_bps) in_avg, avg(out_bps) out_avg, max(in_bps) in_max, max(out_bps) out_max
       FROM iface_samples
      WHERE ts >= $1 AND ts < $2
      GROUP BY iface
      ORDER BY max(util_pct) DESC NULLS LAST`,
    [gteIso, ltIso]
  ).catch(() => []);
  return rows.map((r) => {
    const n = Number(r.n) || 0;
    return {
      iface: r.iface,
      muestras: n,
      utilProm: Math.round((Number(r.util_avg) || 0) * 10) / 10,
      utilPico: Math.round((Number(r.util_max) || 0) * 10) / 10,
      inPromBps: Math.round(Number(r.in_avg) || 0),
      outPromBps: Math.round(Number(r.out_avg) || 0),
      inPicoBps: Math.round(Number(r.in_max) || 0),
      outPicoBps: Math.round(Number(r.out_max) || 0),
      disponibilidadPct: n ? Math.round((Number(r.up) / n) * 1000) / 10 : 0,
    };
  });
}

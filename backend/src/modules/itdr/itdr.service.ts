/**
 * ITDR avanzado (Identity Threat Detection & Response) sobre los logins de
 * Microsoft 365 / Entra ID que ya llegan a Wazuh (data.office365.*):
 *   - VIAJE IMPOSIBLE: dos inicios de sesión exitosos del mismo usuario desde
 *     ubicaciones cuya distancia no se puede cubrir en el tiempo transcurrido
 *     (velocidad implícita > umbral). Excluye egresos VPN/relay conocidos
 *     (reusa isTrustedEgress de office365) para no marcar la VPN corporativa.
 *   - MFA-FATIGUE: ráfaga de fallos de MFA (ErrorNumber 500121/500571) contra
 *     un usuario — el atacante tiene la contraseña y bombardea el MFA. Si tras
 *     la ráfaga hubo un login exitoso desde esa IP => probable cuenta cedida.
 * Persiste hallazgos priorizados. Es visibilidad + alerta (no bloquea).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';
import { geolocate, isPublicIP } from '../geo/geoip.service';
import { isTrustedEgress } from '../office365/o365.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
const MFA_ERRORS = ['500121', '500571']; // fallo/denegación durante el MFA
type Sev = 'critica' | 'alta' | 'media';

const MAX_KMH = Number(env.ITDR_MAX_KMH) || 900;   // vuelo comercial ~900 km/h
const MIN_KM = Number(env.ITDR_MIN_KM) || 500;     // ignora saltos de geo cortos (jitter de geoIP)
const MFA_MIN = Number(env.ITDR_MFA_MIN) || 5;

export function isItdrEnabled(): boolean {
  return String(env.ITDR_ENABLED ?? 'true').toLowerCase() !== 'false';
}

function haversineKm(aLat: number, aLon: number, bLat: number, bLon: number): number {
  const R = 6371, toRad = (d: number): number => (d * Math.PI) / 180;
  const dLat = toRad(bLat - aLat), dLon = toRad(bLon - aLon);
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}

interface IdxResp<T> { aggregations?: T }
interface UserIpBuckets {
  u: { buckets: { key: string; ip: { buckets: { key: string; doc_count: number; first: { value: number }; last: { value: number } }[] } }[] };
}

function client() { return getIndexerClient(); }

async function addFinding(f: { usuario: string; tipo: string; ref: string; severidad: Sev; detalle: string; meta: unknown }): Promise<boolean> {
  const rows = await query<{ nuevo: boolean }>(
    `INSERT INTO itdr_findings (usuario, tipo, ref, severidad, detalle, meta, estado, ultima_vez)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,'open', now())
     ON CONFLICT (usuario, tipo, ref) DO UPDATE
       SET severidad=EXCLUDED.severidad, detalle=EXCLUDED.detalle, meta=EXCLUDED.meta, ultima_vez=now(),
           estado = CASE WHEN itdr_findings.estado='dismissed' THEN 'dismissed' ELSE 'open' END
     RETURNING (xmax = 0) AS nuevo`,
    [f.usuario, f.tipo, f.ref, f.severidad, f.detalle, JSON.stringify(f.meta)],
  );
  return rows[0]?.nuevo ?? false;
}

export interface ItdrNew { usuario: string; tipo: string; severidad: Sev; detalle: string }
export interface ItdrScan { window: string; viajeImposible: number; mfaFatigue: number; nuevos: number; nuevosList: ItdrNew[] }

export async function scan(rangeIn = '24h'): Promise<ItdrScan> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const gte = RANGE[range];
  const nuevosList: ItdrNew[] = [];
  const track = async (usuario: string, tipo: string, ref: string, sev: Sev, detalle: string, meta: unknown): Promise<void> => {
    if (await addFinding({ usuario, tipo, ref, severidad: sev, detalle, meta })) nuevosList.push({ usuario, tipo, severidad: sev, detalle });
  };

  // --- Q1: logins exitosos por usuario -> IP (first/last) ---
  const { data: q1 } = await client().post<IdxResp<UserIpBuckets>>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { term: { 'data.office365.Operation': 'UserLoggedIn' } }] } },
    aggs: { u: { terms: { field: 'data.office365.UserId', size: 500 }, aggs: { ip: { terms: { field: 'data.office365.ClientIP', size: 30 }, aggs: { first: { min: { field: '@timestamp' } }, last: { max: { field: '@timestamp' } } } } } } },
  });

  const successSet = new Set<string>(); // `${user}|${ip}`
  let viajeImposible = 0;
  for (const ub of q1.aggregations?.u?.buckets ?? []) {
    const user = ub.key;
    for (const ib of ub.ip.buckets) successSet.add(`${user}|${ib.key}`);
    if (!user.includes('@')) continue; // solo UPN reales

    // ubicaciones geolocalizables, públicas y NO de VPN/relay confiable
    const locs = ub.ip.buckets
      .filter((b) => isPublicIP(b.key) && !isTrustedEgress(b.key))
      .map((b) => ({ ip: b.key, first: b.first.value, last: b.last.value, geo: geolocate(b.key) }))
      .filter((x): x is { ip: string; first: number; last: number; geo: NonNullable<ReturnType<typeof geolocate>> } => !!x.geo)
      .sort((a, b) => a.first - b.first);

    // peor par (mayor velocidad implícita) con distancia significativa
    let worst: { from: typeof locs[number]; to: typeof locs[number]; km: number; horas: number; kmh: number } | null = null;
    for (let i = 0; i < locs.length; i++) {
      for (let j = 0; j < locs.length; j++) {
        if (i === j) continue;
        const a = locs[i], b = locs[j];
        if (a.last > b.first) continue; // a ocurre antes que b
        const km = haversineKm(a.geo.lat, a.geo.lon, b.geo.lat, b.geo.lon);
        if (km < MIN_KM) continue;
        const horas = Math.max((b.first - a.last) / 3_600_000, 0.02);
        const kmh = km / horas;
        if (kmh > MAX_KMH && (!worst || kmh > worst.kmh)) worst = { from: a, to: b, km, horas, kmh };
      }
    }
    if (worst) {
      viajeImposible++;
      const sev: Sev = worst.kmh > 5000 ? 'critica' : 'alta';
      const fc = `${worst.from.geo.city || '?'}, ${worst.from.geo.country}`;
      const tc = `${worst.to.geo.city || '?'}, ${worst.to.geo.country}`;
      await track(user, 'impossible_travel', `${worst.from.geo.isoCode}->${worst.to.geo.isoCode}`, sev,
        `Viaje imposible: ${fc} → ${tc} en ${worst.horas.toFixed(1)} h (${Math.round(worst.km)} km, ~${Math.round(worst.kmh)} km/h)`,
        { fromIp: worst.from.ip, from: fc, toIp: worst.to.ip, to: tc, km: Math.round(worst.km), horas: Number(worst.horas.toFixed(2)), kmh: Math.round(worst.kmh) });
    }
  }

  // --- Q2: fallos de MFA por usuario -> IP ---
  const { data: q2 } = await client().post<IdxResp<UserIpBuckets>>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { term: { 'data.office365.Operation': 'UserLoginFailed' } }, { terms: { 'data.office365.ErrorNumber': MFA_ERRORS } }] } },
    aggs: { u: { terms: { field: 'data.office365.UserId', size: 300 }, aggs: { ip: { terms: { field: 'data.office365.ClientIP', size: 20 }, aggs: { first: { min: { field: '@timestamp' } }, last: { max: { field: '@timestamp' } } } } } } },
  });

  let mfaFatigue = 0;
  for (const ub of q2.aggregations?.u?.buckets ?? []) {
    const user = ub.key;
    if (!user.includes('@')) continue;
    for (const ib of ub.ip.buckets) {
      if (ib.doc_count < MFA_MIN) continue;
      mfaFatigue++;
      const spanMin = Math.round((ib.last.value - ib.first.value) / 60000);
      const geo = isPublicIP(ib.key) ? geolocate(ib.key) : null;
      const donde = geo ? ` (${geo.city || geo.country})` : '';
      const cedida = successSet.has(`${user}|${ib.key}`);
      const sev: Sev = cedida ? 'critica' : 'alta';
      await track(user, 'mfa_fatigue', ib.key, sev,
        `MFA-fatigue: ${ib.doc_count} rechazos de MFA desde ${ib.key}${donde} en ${spanMin} min${cedida ? ' — ¡y hubo un inicio de sesión EXITOSO desde esa IP! (posible cuenta cedida)' : ''}`,
        { ip: ib.key, intentos: ib.doc_count, spanMin, endedInSuccess: cedida, pais: geo?.country ?? null });
    }
  }

  await query("INSERT INTO itdr_meta (k, v) VALUES ('last_scan', now()::text) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v").catch(() => undefined);
  return { window: range, viajeImposible, mfaFatigue, nuevos: nuevosList.length, nuevosList };
}

// --- Lecturas ---
export interface ItdrFinding { id: string; usuario: string; tipo: string; ref: string; severidad: Sev; detalle: string; meta: unknown; estado: string; primera_vez: string; ultima_vez: string }
const SEV_ORDER = "CASE severidad WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 ELSE 2 END";

export async function getOverview(): Promise<unknown> {
  const bySev = await query<{ severidad: string; n: number }>("SELECT severidad, count(*)::int AS n FROM itdr_findings WHERE estado='open' GROUP BY severidad");
  const byTipo = await query<{ tipo: string; n: number }>("SELECT tipo, count(*)::int AS n FROM itdr_findings WHERE estado='open' GROUP BY tipo");
  const top = await query<ItdrFinding>(`SELECT id,usuario,tipo,ref,severidad,detalle,meta,estado,primera_vez,ultima_vez FROM itdr_findings WHERE estado='open' ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 50`);
  const meta = await query<{ v: string }>("SELECT v FROM itdr_meta WHERE k='last_scan'").catch(() => [] as { v: string }[]);
  const sev: Record<string, number> = { critica: 0, alta: 0, media: 0 };
  for (const s of bySev) sev[s.severidad] = s.n;
  const tipo: Record<string, number> = { impossible_travel: 0, mfa_fatigue: 0 };
  for (const t of byTipo) tipo[t.tipo] = t.n;
  return { severidad: sev, tipo, top, lastScan: meta[0]?.v ?? null };
}
export async function listFindings(opts: { estado?: string; tipo?: string } = {}): Promise<ItdrFinding[]> {
  const estado = opts.estado || 'open';
  const cols = 'id,usuario,tipo,ref,severidad,detalle,meta,estado,primera_vez,ultima_vez';
  if (opts.tipo) return query<ItdrFinding>(`SELECT ${cols} FROM itdr_findings WHERE estado=$1 AND tipo=$2 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado, opts.tipo]);
  return query<ItdrFinding>(`SELECT ${cols} FROM itdr_findings WHERE estado=$1 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado]);
}
export async function setStatus(id: string, estado: string): Promise<void> {
  if (!['open', 'resolved', 'dismissed'].includes(estado)) throw new HttpError(400, 'Estado inválido');
  await query('UPDATE itdr_findings SET estado=$2, ultima_vez=now() WHERE id=$1', [id, estado]);
}

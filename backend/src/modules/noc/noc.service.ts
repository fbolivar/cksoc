/**
 * NOC — Monitoreo de disponibilidad (uptime). Chequeos activos a dispositivos y
 * servicios (ICMP/TCP/HTTP), latencia, estado up/down con antirrebote, historial
 * de transiciones y alertas. En vivo contra una tabla propia (noc_targets/noc_events).
 *
 * No toca el entorno del cliente: solo hace ping/conexión de prueba (lectura).
 */
import { execFile } from 'node:child_process';
import net from 'node:net';
import crypto from 'node:crypto';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

export type CheckKind = 'icmp' | 'tcp' | 'http';
export type NocStatus = 'up' | 'down' | 'unknown';

export interface NocTarget {
  id: string; name: string; host: string; kind: CheckKind; port: number | null; path: string | null;
  grupo: string; enabled: boolean; status: NocStatus; latency_ms: number | null;
  last_check: string | null; last_change: string | null; since: string | null; fail_count: number;
}

const DOWN_AFTER = Number(process.env.NOC_DOWN_AFTER ?? 2); // fallos consecutivos para marcar DOWN (antirrebote)
const TIMEOUT_MS = Number(process.env.NOC_TIMEOUT_MS ?? 3000);
const CONCURRENCY = Number(process.env.NOC_CONCURRENCY ?? 12);

// ---------- chequeos ----------
function pingICMP(host: string): Promise<{ up: boolean; ms: number | null }> {
  return new Promise((resolve) => {
    const started = Date.now();
    execFile('ping', ['-c', '1', '-W', String(Math.ceil(TIMEOUT_MS / 1000)), host], { timeout: TIMEOUT_MS + 1500 }, (err, stdout) => {
      if (err) return resolve({ up: false, ms: null });
      const m = /time[=<]([\d.]+)\s*ms/i.exec(stdout);
      resolve({ up: true, ms: m ? Math.round(parseFloat(m[1])) : Date.now() - started });
    });
  });
}
function checkTCP(host: string, port: number): Promise<{ up: boolean; ms: number | null }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = new net.Socket();
    let done = false;
    const fin = (up: boolean) => { if (done) return; done = true; try { sock.destroy(); } catch { /* */ } resolve({ up, ms: up ? Date.now() - started : null }); };
    sock.setTimeout(TIMEOUT_MS);
    sock.once('connect', () => fin(true));
    sock.once('timeout', () => fin(false));
    sock.once('error', () => fin(false));
    sock.connect(port, host);
  });
}
async function checkHTTP(target: string): Promise<{ up: boolean; ms: number | null }> {
  const url = /^https?:\/\//i.test(target) ? target : `http://${target}`;
  const started = Date.now();
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal });
    return { up: r.status < 500, ms: Date.now() - started };
  } catch { return { up: false, ms: null }; }
  finally { clearTimeout(to); }
}
async function checkOne(t: NocTarget): Promise<{ up: boolean; ms: number | null }> {
  try {
    if (t.kind === 'tcp' && t.port) return await checkTCP(t.host, t.port);
    if (t.kind === 'http') return await checkHTTP(t.path ? `${t.host}${t.path}` : t.host);
    return await pingICMP(t.host);
  } catch { return { up: false, ms: null }; }
}

// ---------- persistencia ----------
async function listRaw(onlyEnabled = false): Promise<NocTarget[]> {
  const rows = await query<NocTarget>(
    `SELECT id, name, host, kind, port, path, grupo, enabled, status, latency_ms,
            last_check, last_change, since, fail_count
       FROM noc_targets ${onlyEnabled ? 'WHERE enabled = TRUE' : ''} ORDER BY grupo, name`
  );
  return rows;
}

// Corre todos los chequeos (con límite de concurrencia), actualiza estado y registra transiciones.
export async function runChecks(): Promise<{ checked: number; transitions: { name: string; host: string; to: NocStatus; downMin: number | null }[] }> {
  const targets = await listRaw(true);
  const transitions: { name: string; host: string; to: NocStatus; downMin: number | null }[] = [];
  let idx = 0;
  async function worker() {
    while (idx < targets.length) {
      const t = targets[idx++];
      const { up, ms } = await checkOne(t);
      const now = new Date();
      let newStatus: NocStatus = t.status;
      let failCount = t.fail_count;
      if (up) { failCount = 0; newStatus = 'up'; }
      else { failCount = t.fail_count + 1; if (failCount >= DOWN_AFTER) newStatus = 'down'; }
      const changed = newStatus !== t.status && t.status !== 'unknown';
      const firstKnown = t.status === 'unknown' && newStatus !== 'unknown';
      try {
        await query(
          `UPDATE noc_targets SET status=$2, latency_ms=$3, fail_count=$4, last_check=now()
             ${newStatus !== t.status ? ', last_change=now(), since=now()' : ''}
           WHERE id=$1`,
          [t.id, newStatus, up ? ms : null, failCount]
        );
        if (changed || firstKnown) {
          let downMin: number | null = null;
          if (newStatus === 'up' && t.since) downMin = Math.max(0, Math.round((now.getTime() - new Date(t.since).getTime()) / 60000));
          await query(`INSERT INTO noc_events (target_id, name, status, latency_ms) VALUES ($1,$2,$3,$4)`, [t.id, t.name, newStatus, up ? ms : null]);
          if (changed) transitions.push({ name: t.name, host: t.host, to: newStatus, downMin });
        }
      } catch (e) { logger.warn({ err: e instanceof Error ? e.message : e, target: t.name }, 'NOC: fallo actualizando estado'); }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, () => worker()));
  return { checked: targets.length, transitions };
}

// ---------- API del módulo ----------
export interface NocOverview {
  kpis: { total: number; up: number; down: number; disabled: number; avgLatency: number | null };
  grupos: { grupo: string; targets: NocTarget[] }[];
  eventos: { name: string; status: NocStatus; latency_ms: number | null; at: string }[];
  lastRun: string | null;
}
export async function getOverview(): Promise<NocOverview> {
  const all = await listRaw(false);
  const enabled = all.filter((t) => t.enabled);
  const up = enabled.filter((t) => t.status === 'up');
  const down = enabled.filter((t) => t.status === 'down');
  const lats = up.map((t) => t.latency_ms).filter((x): x is number => x != null);
  const grupos = new Map<string, NocTarget[]>();
  for (const t of all) { const g = t.grupo || 'General'; (grupos.get(g) ?? grupos.set(g, []).get(g)!).push(t); }
  const eventos = await query<{ name: string; status: NocStatus; latency_ms: number | null; at: string }>(
    `SELECT name, status, latency_ms, at FROM noc_events ORDER BY at DESC LIMIT 40`
  );
  return {
    kpis: {
      total: enabled.length, up: up.length, down: down.length, disabled: all.length - enabled.length,
      avgLatency: lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : null,
    },
    grupos: [...grupos.entries()].map(([grupo, targets]) => ({ grupo, targets })),
    eventos,
    lastRun: all.reduce<string | null>((mx, t) => (t.last_check && (!mx || t.last_check > mx) ? t.last_check : mx), null),
  };
}

export async function addTarget(input: { name: string; host: string; kind?: CheckKind; port?: number | null; path?: string | null; grupo?: string }): Promise<string> {
  const id = crypto.randomUUID();
  const kind: CheckKind = input.kind && ['icmp', 'tcp', 'http'].includes(input.kind) ? input.kind : 'icmp';
  await query(
    `INSERT INTO noc_targets (id, name, host, kind, port, path, grupo, enabled, status, fail_count)
       VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,'unknown',0)`,
    [id, input.name.trim(), input.host.trim(), kind, kind === 'tcp' ? input.port ?? null : null, kind === 'http' ? input.path ?? null : null, (input.grupo || 'General').trim()]
  );
  return id;
}
export async function setEnabled(id: string, enabled: boolean): Promise<void> {
  await query(`UPDATE noc_targets SET enabled=$2 ${enabled ? ", status='unknown', fail_count=0" : ''} WHERE id=$1`, [id, enabled]);
}
export async function deleteTarget(id: string): Promise<void> { await query(`DELETE FROM noc_targets WHERE id=$1`, [id]); }

export async function isNocEnabled(): Promise<boolean> { return String(process.env.NOC_ENABLED ?? 'true').toLowerCase() !== 'false'; }

// Crea las tablas si no existen y siembra objetivos de infraestructura (idempotente).
export async function ensureNocSchema(): Promise<void> {
  await query(`CREATE TABLE IF NOT EXISTS noc_targets (
    id uuid PRIMARY KEY, name text NOT NULL, host text NOT NULL, kind text NOT NULL DEFAULT 'icmp',
    port int, path text, grupo text DEFAULT 'General', enabled boolean NOT NULL DEFAULT TRUE,
    status text NOT NULL DEFAULT 'unknown', latency_ms int, last_check timestamptz,
    last_change timestamptz, since timestamptz, fail_count int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now())`);
  await query(`CREATE TABLE IF NOT EXISTS noc_events (
    id bigserial PRIMARY KEY, target_id uuid, name text, status text, latency_ms int,
    at timestamptz NOT NULL DEFAULT now())`);
  await query(`CREATE INDEX IF NOT EXISTS noc_events_at_idx ON noc_events (at DESC)`);
  const c = await query<{ n: number }>(`SELECT count(*)::int AS n FROM noc_targets`);
  if ((c[0]?.n ?? 0) === 0 && String(process.env.NOC_SEED ?? 'true').toLowerCase() !== 'false') {
    const seed: { name: string; host: string; kind: CheckKind; port?: number; path?: string; grupo: string }[] = [
      { name: 'SOC · Proxmox (pmx)', host: '192.168.20.10', kind: 'icmp', grupo: 'Infraestructura SOC' },
      { name: 'SOC · Wazuh', host: '192.168.20.11', kind: 'icmp', grupo: 'Infraestructura SOC' },
      { name: 'SOC · Velociraptor', host: '192.168.20.12', kind: 'icmp', grupo: 'Infraestructura SOC' },
      { name: 'SOC · Web/App (nginx)', host: '127.0.0.1', kind: 'tcp', port: 443, grupo: 'Infraestructura SOC' },
      { name: 'Internet (Google DNS)', host: '8.8.8.8', kind: 'icmp', grupo: 'Enlaces/Internet' },
      { name: 'Internet (Cloudflare DNS)', host: '1.1.1.1', kind: 'icmp', grupo: 'Enlaces/Internet' },
    ];
    for (const s of seed) await addTarget(s);
    logger.info({ n: seed.length }, 'NOC: objetivos de infraestructura sembrados');
  }
}

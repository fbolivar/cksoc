/**
 * NOC — Monitoreo de disponibilidad (uptime). Chequeos activos a dispositivos y
 * servicios (ICMP/TCP/HTTP), latencia, estado up/down con antirrebote, historial
 * de transiciones, uptime % histórico y métricas SNMP-lite (CPU/RAM/interfaces/
 * temperatura) para equipos de red. En vivo contra tablas propias (noc_targets/noc_events).
 *
 * No toca el entorno del cliente: solo hace ping/conexión de prueba y consultas
 * SNMP de solo lectura (GET/WALK).
 */
import { execFile } from 'node:child_process';
import net from 'node:net';
import crypto from 'node:crypto';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

export type CheckKind = 'icmp' | 'tcp' | 'http';
export type NocStatus = 'up' | 'down' | 'unknown';

export interface NocUptime { d1: number | null; d7: number | null; d30: number | null }
export interface NocSnmp {
  sysDescr: string | null; uptimeS: number | null; cpuPct: number | null; memPct: number | null;
  ifUp: number | null; ifTotal: number | null; tempC: number | null;
}
export interface NocTarget {
  id: string; name: string; host: string; kind: CheckKind; port: number | null; path: string | null;
  grupo: string; enabled: boolean; status: NocStatus; latency_ms: number | null;
  last_check: string | null; last_change: string | null; since: string | null; fail_count: number;
  snmp_enabled: boolean; snmp_community?: string | null;
  sys_descr: string | null; uptime_s: number | null; cpu_pct: number | null; mem_pct: number | null;
  if_up: number | null; if_total: number | null; temp_c: number | null; snmp_at: string | null;
  uptime?: NocUptime;
}

const DOWN_AFTER = Number(process.env.NOC_DOWN_AFTER ?? 2); // fallos consecutivos para marcar DOWN (antirrebote)
const TIMEOUT_MS = Number(process.env.NOC_TIMEOUT_MS ?? 3000);
const CONCURRENCY = Number(process.env.NOC_CONCURRENCY ?? 12);
const SNMP_TIMEOUT_MS = Number(process.env.NOC_SNMP_TIMEOUT_MS ?? 2500);

// Grupos considerados "infraestructura propia del SOC" (no son del cliente).
export const SOC_GROUPS = ['Infraestructura SOC', 'Enlaces/Internet'];

// ---------- chequeos de disponibilidad ----------
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

// ---------- SNMP-lite (solo lectura, best-effort) ----------
// OIDs estándar: sysDescr/sysUpTime (SNMPv2-MIB), ifOperStatus (IF-MIB),
// hrProcessorLoad (HOST-RESOURCES), memoria/CPU UCD-SNMP, temperatura ENTITY-SENSOR.
async function snmpLite(host: string, community: string): Promise<NocSnmp | null> {
  let snmp: any;
  try { snmp = require('net-snmp'); } catch { return null; }
  const res: NocSnmp = { sysDescr: null, uptimeS: null, cpuPct: null, memPct: null, ifUp: null, ifTotal: null, tempC: null };
  let session: any;
  try { session = snmp.createSession(host, community || 'public', { timeout: SNMP_TIMEOUT_MS, retries: 0, version: snmp.Version2c }); }
  catch { return null; }

  const get = (oids: string[]): Promise<Record<string, any>> => new Promise((resolve) => {
    try {
      session.get(oids, (err: any, vbs: any[]) => {
        const o: Record<string, any> = {};
        if (!err && vbs) for (const vb of vbs) { if (!snmp.isVarbindError(vb)) o[vb.oid] = vb.value; }
        resolve(o);
      });
    } catch { resolve({}); }
  });
  const walk = (oid: string): Promise<any[]> => new Promise((resolve) => {
    const vals: any[] = []; let settled = false;
    const fin = () => { if (settled) return; settled = true; resolve(vals); };
    try { session.subtree(oid, 20, (vbs: any[]) => { for (const vb of vbs) { if (!snmp.isVarbindError(vb)) vals.push(vb.value); } }, fin); }
    catch { fin(); }
    setTimeout(fin, SNMP_TIMEOUT_MS + 1500);
  });

  try {
    const sc = await get(['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.3.0']); // sysDescr, sysUpTime
    if (sc['1.3.6.1.2.1.1.1.0'] != null) res.sysDescr = String(sc['1.3.6.1.2.1.1.1.0']).replace(/\s+/g, ' ').slice(0, 200);
    if (sc['1.3.6.1.2.1.1.3.0'] != null) { const t = Number(sc['1.3.6.1.2.1.1.3.0']); if (Number.isFinite(t)) res.uptimeS = Math.round(t / 100); }

    const ifst = await walk('1.3.6.1.2.1.2.2.1.8'); // ifOperStatus (1=up)
    if (ifst.length) { res.ifTotal = ifst.length; res.ifUp = ifst.filter((v) => Number(v) === 1).length; }

    const cpu = await walk('1.3.6.1.2.1.25.3.3.1.2'); // hrProcessorLoad (%)
    if (cpu.length) res.cpuPct = Math.round(cpu.reduce((a, b) => a + Number(b), 0) / cpu.length);
    else {
      const uc = await get(['1.3.6.1.4.1.2021.11.11.0']); // UCD ssCpuIdle → 100-idle
      const idle = Number(uc['1.3.6.1.4.1.2021.11.11.0']);
      if (Number.isFinite(idle)) res.cpuPct = Math.max(0, Math.min(100, 100 - idle));
    }
    if (res.cpuPct == null) { // SonicWALL sonicCurrentCPUUtil (%)
      const sw = await get(['1.3.6.1.4.1.8741.1.3.1.3.0']);
      const v = Number(sw['1.3.6.1.4.1.8741.1.3.1.3.0']);
      if (Number.isFinite(v)) res.cpuPct = Math.max(0, Math.min(100, Math.round(v)));
    }

    // UCD memTotalReal, memAvailReal, memBuffer, memCached (KB). Buffers+caché son
    // memoria reclamable → se descuentan para reportar el uso REAL (equivalente a
    // MemAvailable de Linux), no la caché de disco (que haría ver ~99% falsamente).
    const mem = await get(['1.3.6.1.4.1.2021.4.5.0', '1.3.6.1.4.1.2021.4.6.0', '1.3.6.1.4.1.2021.4.14.0', '1.3.6.1.4.1.2021.4.15.0']);
    const tot = Number(mem['1.3.6.1.4.1.2021.4.5.0']); const av = Number(mem['1.3.6.1.4.1.2021.4.6.0']);
    const buf = Number(mem['1.3.6.1.4.1.2021.4.14.0']) || 0; const cache = Number(mem['1.3.6.1.4.1.2021.4.15.0']) || 0;
    if (tot > 0 && Number.isFinite(av)) res.memPct = Math.max(0, Math.min(100, Math.round((100 * (tot - av - buf - cache)) / tot)));
    if (res.memPct == null) { // SonicWALL sonicCurrentRAMUtil (%)
      const sw = await get(['1.3.6.1.4.1.8741.1.3.1.4.0']);
      const v = Number(sw['1.3.6.1.4.1.8741.1.3.1.4.0']);
      if (Number.isFinite(v)) res.memPct = Math.max(0, Math.min(100, Math.round(v)));
    }

    const temp = await walk('1.3.6.1.2.1.99.1.1.1.4'); // ENTITY-SENSOR entPhySensorValue (best-effort)
    if (temp.length) { const t = Number(temp[0]); if (Number.isFinite(t) && t > 0 && t < 150) res.tempC = Math.round(t); }
  } catch { /* best-effort */ }
  finally { try { session.close(); } catch { /* */ } }

  const any = res.sysDescr || res.uptimeS != null || res.cpuPct != null || res.memPct != null || res.ifTotal != null || res.tempC != null;
  return any ? res : null;
}

// ---------- persistencia ----------
async function listRaw(onlyEnabled = false): Promise<NocTarget[]> {
  const rows = await query<NocTarget>(
    `SELECT id, name, host, kind, port, path, grupo, enabled, status, latency_ms,
            last_check, last_change, since, fail_count,
            snmp_enabled, snmp_community, sys_descr, uptime_s, cpu_pct, mem_pct,
            if_up, if_total, temp_c, snmp_at
       FROM noc_targets ${onlyEnabled ? 'WHERE enabled = TRUE' : ''} ORDER BY grupo, name`
  );
  return rows;
}

// Corre todos los chequeos (con límite de concurrencia), actualiza estado, registra
// transiciones y refresca métricas SNMP de los objetivos que lo tengan habilitado.
export async function runChecks(): Promise<{ checked: number; transitions: { name: string; host: string; grupo: string; to: NocStatus; downMin: number | null }[] }> {
  const targets = await listRaw(true);
  const transitions: { name: string; host: string; grupo: string; to: NocStatus; downMin: number | null }[] = [];
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
          if (changed) transitions.push({ name: t.name, host: t.host, grupo: t.grupo || 'General', to: newStatus, downMin });
        }
        // SNMP-lite: solo si está habilitado y el equipo respondió (está arriba).
        if (t.snmp_enabled && up) {
          const m = await snmpLite(t.host, t.snmp_community || 'public');
          if (m) {
            await query(
              `UPDATE noc_targets SET sys_descr=$2, uptime_s=$3, cpu_pct=$4, mem_pct=$5, if_up=$6, if_total=$7, temp_c=$8, snmp_at=now() WHERE id=$1`,
              [t.id, m.sysDescr, m.uptimeS, m.cpuPct, m.memPct, m.ifUp, m.ifTotal, m.tempC]
            );
          }
        }
      } catch (e) { logger.warn({ err: e instanceof Error ? e.message : e, target: t.name }, 'NOC: fallo actualizando estado'); }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, () => worker()));
  return { checked: targets.length, transitions };
}

// ---------- uptime % histórico (a partir de las transiciones) ----------
// Calcula el % de tiempo "up" en una ventana [start, now] usando los eventos de
// transición. Antes del primer evento se asume disponible (optimista coherente
// con el estado inicial sembrado). evs debe venir ordenado ascendente por fecha.
function uptimePct(evs: { at: string; status: NocStatus }[], startMs: number, nowMs: number): number {
  const span = nowMs - startMs;
  if (span <= 0) return 100;
  let state: NocStatus = 'up';
  for (const e of evs) { if (new Date(e.at).getTime() <= startMs) state = e.status; else break; }
  let downMs = 0; let cursor = startMs;
  for (const e of evs) {
    const tms = new Date(e.at).getTime();
    if (tms <= startMs) continue;
    if (tms > nowMs) break;
    if (state === 'down') downMs += tms - cursor;
    cursor = tms; state = e.status;
  }
  if (state === 'down') downMs += nowMs - cursor;
  return Math.max(0, Math.min(100, 100 * (1 - downMs / span)));
}

// ---------- API del módulo ----------
export interface NocOverview {
  kpis: { total: number; up: number; down: number; disabled: number; avgLatency: number | null; avgUptime30: number | null };
  grupos: { grupo: string; esCliente: boolean; targets: NocTarget[] }[];
  eventos: { name: string; status: NocStatus; latency_ms: number | null; at: string }[];
  lastRun: string | null;
}
export async function getOverview(): Promise<NocOverview> {
  const all = await listRaw(false);
  const enabled = all.filter((t) => t.enabled);
  const up = enabled.filter((t) => t.status === 'up');
  const down = enabled.filter((t) => t.status === 'down');
  const lats = up.map((t) => t.latency_ms).filter((x): x is number => x != null);

  // uptime histórico: traigo 30d de eventos una vez y calculo 3 ventanas en memoria.
  const now = Date.now();
  const evAll = await query<{ target_id: string; at: string; status: NocStatus }>(
    `SELECT target_id, at, status FROM noc_events WHERE at > now() - interval '30 days' ORDER BY at ASC`
  );
  const byTarget = new Map<string, { at: string; status: NocStatus }[]>();
  for (const e of evAll) { const a = byTarget.get(e.target_id) ?? []; a.push({ at: e.at, status: e.status }); byTarget.set(e.target_id, a); }
  const uptime30s: number[] = [];
  for (const t of all) {
    const evs = byTarget.get(t.id) ?? [];
    const u: NocUptime = {
      d1: Math.round(uptimePct(evs, now - 1 * 86400000, now) * 100) / 100,
      d7: Math.round(uptimePct(evs, now - 7 * 86400000, now) * 100) / 100,
      d30: Math.round(uptimePct(evs, now - 30 * 86400000, now) * 100) / 100,
    };
    t.uptime = u;
    delete t.snmp_community; // no exponer la comunidad SNMP al frontend
    if (t.enabled && u.d30 != null) uptime30s.push(u.d30);
  }

  const grupos = new Map<string, NocTarget[]>();
  for (const t of all) { const g = t.grupo || 'General'; (grupos.get(g) ?? grupos.set(g, []).get(g)!).push(t); }
  const eventos = await query<{ name: string; status: NocStatus; latency_ms: number | null; at: string }>(
    `SELECT name, status, latency_ms, at FROM noc_events ORDER BY at DESC LIMIT 40`
  );
  return {
    kpis: {
      total: enabled.length, up: up.length, down: down.length, disabled: all.length - enabled.length,
      avgLatency: lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : null,
      avgUptime30: uptime30s.length ? Math.round((uptime30s.reduce((a, b) => a + b, 0) / uptime30s.length) * 100) / 100 : null,
    },
    grupos: [...grupos.entries()].map(([grupo, targets]) => ({ grupo, esCliente: !SOC_GROUPS.includes(grupo), targets })),
    eventos,
    lastRun: all.reduce<string | null>((mx, t) => (t.last_check && (!mx || t.last_check > mx) ? t.last_check : mx), null),
  };
}

// Reporte de disponibilidad: uptime por objetivo + conteo de caídas en la ventana.
export async function getReport(days = 30): Promise<{
  dias: number;
  objetivos: { name: string; host: string; grupo: string; esCliente: boolean; status: NocStatus; uptimePct: number; caidas: number; downMin: number }[];
}> {
  const d = Math.max(1, Math.min(90, Math.round(days)));
  const now = Date.now(); const startMs = now - d * 86400000;
  const all = await listRaw(false);
  const evAll = await query<{ target_id: string; at: string; status: NocStatus }>(
    `SELECT target_id, at, status FROM noc_events WHERE at > now() - ($1 || ' days')::interval ORDER BY at ASC`, [d]
  );
  const byTarget = new Map<string, { at: string; status: NocStatus }[]>();
  for (const e of evAll) { const a = byTarget.get(e.target_id) ?? []; a.push({ at: e.at, status: e.status }); byTarget.set(e.target_id, a); }
  const objetivos = all.filter((t) => t.enabled).map((t) => {
    const evs = byTarget.get(t.id) ?? [];
    const pct = uptimePct(evs, startMs, now);
    const caidas = evs.filter((e) => e.status === 'down' && new Date(e.at).getTime() >= startMs).length;
    const downMin = Math.round(((100 - pct) / 100) * (d * 1440));
    return { name: t.name, host: t.host, grupo: t.grupo || 'General', esCliente: !SOC_GROUPS.includes(t.grupo || 'General'), status: t.status, uptimePct: Math.round(pct * 100) / 100, caidas, downMin };
  }).sort((a, b) => a.uptimePct - b.uptimePct);
  return { dias: d, objetivos };
}

export async function addTarget(input: { name: string; host: string; kind?: CheckKind; port?: number | null; path?: string | null; grupo?: string; snmpEnabled?: boolean; snmpCommunity?: string | null }): Promise<string> {
  const id = crypto.randomUUID();
  const kind: CheckKind = input.kind && ['icmp', 'tcp', 'http'].includes(input.kind) ? input.kind : 'icmp';
  const snmpOn = input.snmpEnabled === true;
  await query(
    `INSERT INTO noc_targets (id, name, host, kind, port, path, grupo, enabled, status, fail_count, snmp_enabled, snmp_community)
       VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,'unknown',0,$8,$9)`,
    [id, input.name.trim(), input.host.trim(), kind, kind === 'tcp' ? input.port ?? null : null, kind === 'http' ? input.path ?? null : null, (input.grupo || 'General').trim(), snmpOn, snmpOn ? (input.snmpCommunity?.trim() || 'public') : null]
  );
  return id;
}
export async function setEnabled(id: string, enabled: boolean): Promise<void> {
  await query(`UPDATE noc_targets SET enabled=$2 ${enabled ? ", status='unknown', fail_count=0" : ''} WHERE id=$1`, [id, enabled]);
}
export async function setSnmp(id: string, enabled: boolean, community?: string | null): Promise<void> {
  await query(
    `UPDATE noc_targets SET snmp_enabled=$2, snmp_community=$3
       ${enabled ? '' : ', sys_descr=NULL, uptime_s=NULL, cpu_pct=NULL, mem_pct=NULL, if_up=NULL, if_total=NULL, temp_c=NULL, snmp_at=NULL'}
     WHERE id=$1`,
    [id, enabled, enabled ? (community?.trim() || 'public') : null]
  );
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
  // columnas SNMP (idempotente, por si la tabla ya existía)
  await query(`ALTER TABLE noc_targets
    ADD COLUMN IF NOT EXISTS snmp_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS snmp_community text,
    ADD COLUMN IF NOT EXISTS sys_descr text,
    ADD COLUMN IF NOT EXISTS uptime_s bigint,
    ADD COLUMN IF NOT EXISTS cpu_pct int,
    ADD COLUMN IF NOT EXISTS mem_pct int,
    ADD COLUMN IF NOT EXISTS if_up int,
    ADD COLUMN IF NOT EXISTS if_total int,
    ADD COLUMN IF NOT EXISTS temp_c int,
    ADD COLUMN IF NOT EXISTS snmp_at timestamptz`);
  await query(`CREATE TABLE IF NOT EXISTS noc_events (
    id bigserial PRIMARY KEY, target_id uuid, name text, status text, latency_ms int,
    at timestamptz NOT NULL DEFAULT now())`);
  await query(`CREATE INDEX IF NOT EXISTS noc_events_at_idx ON noc_events (at DESC)`);
  await query(`CREATE INDEX IF NOT EXISTS noc_events_target_idx ON noc_events (target_id, at)`);
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

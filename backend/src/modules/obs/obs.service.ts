/**
 * Observabilidad — Tendencia histórica de recursos de la infraestructura del SOC.
 * Fuente: API de Proxmox VE del hypervisor (.10) con un token de SOLO LECTURA
 * (rol PVEAuditor). Proxmox ya guarda series RRD (hora/día/semana/mes/año) del
 * nodo y de cada VM; aquí solo se consultan y normalizan. NO corre scheduler ni
 * escribe en la base de datos, y NO toca el entorno del cliente.
 */
import https from 'node:https';
import axios from 'axios';
import { env } from '../../config/env';

// Proxmox usa un certificado interno autofirmado -> no validar la cadena TLS.
const agent = new https.Agent({ rejectUnauthorized: false });

export type Timeframe = 'hour' | 'day' | 'week' | 'month' | 'year';
const TIMEFRAMES: Timeframe[] = ['hour', 'day', 'week', 'month', 'year'];
export function normTf(tf?: string): Timeframe {
  return TIMEFRAMES.includes(tf as Timeframe) ? (tf as Timeframe) : 'day';
}

interface PvCfg { url: string; id: string; secret: string; node: string }
function cfg(): PvCfg | null {
  const url = env.PROXMOX_API_URL;
  const id = env.PROXMOX_API_TOKENID;
  const secret = env.PROXMOX_API_SECRET;
  const node = env.PROXMOX_NODE;
  if (!url || !id || !secret || !node) return null;
  return { url, id, secret, node };
}
export function isObsConfigured(): boolean { return cfg() != null; }

async function pvGet(path: string, params?: Record<string, string>): Promise<unknown> {
  const c = cfg();
  if (!c) throw new Error('Proxmox no configurado');
  const res = await axios.get(`${c.url}${path}`, {
    params,
    httpsAgent: agent,
    timeout: 15000,
    headers: { Authorization: `PVEAPIToken=${c.id}=${c.secret}` },
  });
  return (res.data as { data?: unknown })?.data;
}

// VMs del SOC a graficar (id -> etiqueta amigable).
const VMS: { vmid: number; label: string; rol: string }[] = [
  { vmid: 100, label: 'Wazuh / SIEM', rol: 'Indexer + Manager' },
  { vmid: 101, label: 'Velociraptor', rol: 'DFIR' },
  { vmid: 102, label: 'Aplicación SOC', rol: 'HexWatch (backend + panel)' },
];

export interface ResPoint {
  t: number; cpu: number | null; mem: number | null; disk: number | null;
  load: number | null; iowait: number | null; netin: number | null; netout: number | null; swap: number | null;
}

type Row = Record<string, number | undefined>;

function pct(n: number | undefined | null, d: number | undefined | null): number | null {
  if (n == null || d == null || !d) return null;
  return Math.round((n / d) * 1000) / 10;
}
function cpuPct(v: number | undefined | null): number | null {
  if (v == null) return null;
  return Math.round(v * 1000) / 10;
}

export async function getNodeTrend(tf: Timeframe): Promise<{ ok: boolean; node: string; puntos: ResPoint[]; error?: string }> {
  const c = cfg();
  if (!c) return { ok: false, node: '', puntos: [], error: 'Proxmox no configurado' };
  try {
    const rows = (await pvGet(`/nodes/${c.node}/rrddata`, { timeframe: tf })) as Row[];
    const puntos = (rows || []).filter((r) => r.time).map((r) => ({
      t: (r.time as number) * 1000,
      cpu: cpuPct(r.cpu),
      mem: pct(r.memused, r.memtotal),
      disk: pct(r.rootused, r.roottotal),
      load: r.loadavg != null ? Math.round(r.loadavg * 100) / 100 : null,
      iowait: cpuPct(r.iowait),
      netin: r.netin != null ? Math.round(r.netin) : null,
      netout: r.netout != null ? Math.round(r.netout) : null,
      swap: pct(r.swapused, r.swaptotal),
    }));
    return { ok: true, node: c.node, puntos };
  } catch (e) {
    return { ok: false, node: c.node, puntos: [], error: (e as Error).message };
  }
}

export async function getVmTrend(vmid: number, tf: Timeframe): Promise<{ ok: boolean; vmid: number; puntos: ResPoint[]; error?: string }> {
  const c = cfg();
  if (!c) return { ok: false, vmid, puntos: [], error: 'Proxmox no configurado' };
  try {
    const rows = (await pvGet(`/nodes/${c.node}/qemu/${vmid}/rrddata`, { timeframe: tf })) as Row[];
    const puntos = (rows || []).filter((r) => r.time).map((r) => ({
      t: (r.time as number) * 1000,
      cpu: cpuPct(r.cpu),
      mem: pct(r.mem, r.maxmem),
      disk: pct(r.disk, r.maxdisk),
      load: null,
      iowait: null,
      netin: r.netin != null ? Math.round(r.netin) : null,
      netout: r.netout != null ? Math.round(r.netout) : null,
      swap: null,
    }));
    return { ok: true, vmid, puntos };
  } catch (e) {
    return { ok: false, vmid, puntos: [], error: (e as Error).message };
  }
}

export interface InvEntity {
  kind: 'node' | 'vm'; id: string; vmid?: number; label: string; rol: string;
  status: string; cpu: number | null; mem: number | null; maxmemGB: number | null; uptimeS: number | null;
}

export async function getInventory(): Promise<{ ok: boolean; entidades: InvEntity[]; error?: string }> {
  const c = cfg();
  if (!c) return { ok: false, entidades: [], error: 'Proxmox no configurado' };
  try {
    const nodeStatus = (await pvGet(`/nodes/${c.node}/status`).catch(() => null)) as
      | { cpu?: number; uptime?: number; memory?: { used?: number; total?: number } } | null;
    const ent: InvEntity[] = [];
    ent.push({
      kind: 'node', id: c.node, label: `Hypervisor (${c.node})`, rol: 'Proxmox VE', status: 'online',
      cpu: nodeStatus ? cpuPct(nodeStatus.cpu) : null,
      mem: nodeStatus?.memory ? pct(nodeStatus.memory.used, nodeStatus.memory.total) : null,
      maxmemGB: nodeStatus?.memory?.total ? Math.round((nodeStatus.memory.total / 1073741824) * 10) / 10 : null,
      uptimeS: nodeStatus?.uptime ?? null,
    });
    for (const vm of VMS) {
      const st = (await pvGet(`/nodes/${c.node}/qemu/${vm.vmid}/status/current`).catch(() => null)) as
        | { status?: string; cpu?: number; mem?: number; maxmem?: number; uptime?: number } | null;
      ent.push({
        kind: 'vm', id: `vm/${vm.vmid}`, vmid: vm.vmid, label: vm.label, rol: vm.rol,
        status: st?.status ?? 'unknown',
        cpu: st ? cpuPct(st.cpu) : null,
        mem: st ? pct(st.mem, st.maxmem) : null,
        maxmemGB: st?.maxmem ? Math.round((st.maxmem / 1073741824) * 10) / 10 : null,
        uptimeS: st?.uptime ?? null,
      });
    }
    return { ok: true, entidades: ent };
  } catch (e) {
    return { ok: false, entidades: [], error: (e as Error).message };
  }
}

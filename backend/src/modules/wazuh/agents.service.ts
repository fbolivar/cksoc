/**
 * Servicio de agentes (Wazuh API).
 * Estado agregado y listado de agentes para el panel de gestion del SOC.
 */
import { wazuhApiGet } from './wazuh.api.client';

export interface AgentsSummary {
  total: number;
  active: number;
  disconnected: number;
  neverConnected: number;
  pending: number;
}

export interface AgentItem {
  id: string;
  name: string;
  ip: string;
  status: string;
  os: string;
  version: string;
  lastKeepAlive: string;
}

/** Resumen de conexion de agentes (activos / desconectados / etc.). */
export async function getAgentsSummary(): Promise<AgentsSummary> {
  const data = await wazuhApiGet<{
    connection: {
      active: number;
      disconnected: number;
      never_connected: number;
      pending: number;
      total: number;
    };
  }>('/agents/summary/status');

  const c = data.connection;
  return {
    total: c.total,
    active: c.active,
    disconnected: c.disconnected,
    neverConnected: c.never_connected,
    pending: c.pending,
  };
}

export interface SedeBucket {
  sede: string;
  total: number;
  active: number;
}

/**
 * Distribucion de agentes por "sede". Wazuh no expone un campo sede propio, por
 * lo que se usa el grupo del agente como dimension de ubicacion/sede (es el
 * agrupador real y editable en Wazuh). Los agentes sin grupo caen en "Sin grupo".
 */
export async function getAgentsBySede(): Promise<SedeBucket[]> {
  const data = await wazuhApiGet<{
    affected_items: Array<{ id: string; status: string; group?: string[] }>;
  }>('/agents', { select: 'id,status,group', limit: 1000, sort: 'name' });

  const map = new Map<string, { total: number; active: number }>();
  for (const a of data.affected_items) {
    if (a.id === '000') continue; // el manager no es una sede
    const sede = a.group && a.group.length > 0 ? a.group[0] : 'Sin grupo';
    const cur = map.get(sede) ?? { total: 0, active: 0 };
    cur.total += 1;
    if (a.status === 'active') cur.active += 1;
    map.set(sede, cur);
  }
  return [...map.entries()]
    .map(([sede, v]) => ({ sede, total: v.total, active: v.active }))
    .sort((a, b) => b.total - a.total);
}

/** Listado de agentes con sus datos principales. */
export async function getAgents(limit = 50): Promise<AgentItem[]> {
  const data = await wazuhApiGet<{
    affected_items: Array<{
      id: string;
      name: string;
      ip?: string;
      status: string;
      version?: string;
      lastKeepAlive?: string;
      os?: { name?: string; version?: string };
    }>;
  }>('/agents', {
    limit,
    sort: '-status,name',
    select: 'id,name,ip,status,os.name,os.version,version,lastKeepAlive',
  });

  return data.affected_items.map((a) => ({
    id: a.id,
    name: a.name,
    ip: a.ip ?? '—',
    status: a.status,
    os: [a.os?.name, a.os?.version].filter(Boolean).join(' ') || '—',
    version: a.version ?? '—',
    lastKeepAlive: a.lastKeepAlive ?? '—',
  }));
}

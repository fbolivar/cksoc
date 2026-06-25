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

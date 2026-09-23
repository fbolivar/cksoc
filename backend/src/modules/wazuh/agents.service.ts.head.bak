/**
 * Servicio de agentes (Wazuh API).
 * Estado agregado y listado de agentes para el panel de gestion del SOC.
 */
import { wazuhApiGet, wazuhApiDelete } from './wazuh.api.client';
import { HttpError } from '../auth/auth.service';

export interface AgentsSummary {
  total: number;
  active: number;
  disconnected: number;
  neverConnected: number;
  pending: number;
}

export type AgentKind = 'servidor' | 'estacion';
export type AgentHealth = 'ok' | 'apagado' | 'investigar' | 'alerta' | 'fantasma';

export interface AgentItem {
  id: string;
  name: string;
  ip: string;
  status: string;
  os: string;
  version: string;
  lastKeepAlive: string;
  kind: AgentKind;
  staleDays: number | null;
  health: AgentHealth;
  motivo: string;
  needsAttention: boolean;
}

const AGENT_STALE_DAYS = 7;
function classifyKind(os: string, name: string): AgentKind {
  const o = (os || '').toLowerCase();
  if (/ubuntu|debian|linux|centos|red\s?hat|windows server|server\b/.test(o)) return 'servidor';
  if (/(^|[-_])(gvm-soc|pmx|srv|soc)([-_]|$)/i.test(name)) return 'servidor';
  return 'estacion';
}
function classifyHealth(status: string, staleDays: number | null, kind: AgentKind): { health: AgentHealth; motivo: string } {
  if (status === 'active') return { health: 'ok', motivo: 'Reportando normalmente.' };
  if (status === 'never_connected' || staleDays === null)
    return { health: 'fantasma', motivo: 'Registrado pero NUNCA reportó: registro fantasma. Candidato a eliminar.' };
  if (staleDays >= AGENT_STALE_DAYS)
    return { health: 'investigar', motivo: `Sin reportar hace ${staleDays} días: dado de baja, dañado o agente detenido.` };
  if (kind === 'servidor')
    return { health: 'alerta', motivo: `Servidor desconectado (${staleDays} día(s)).` };
  return { health: 'apagado', motivo: `Estación apagada hace ${staleDays} día(s): normal fuera de horario.` };
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

  const now = Date.now();
  const items = data.affected_items.map((a) => {
    const os = [a.os?.name, a.os?.version].filter(Boolean).join(' ') || '—';
    const lka = a.lastKeepAlive && !a.lastKeepAlive.startsWith('9999') ? a.lastKeepAlive : null;
    const staleDays = lka ? Math.floor((now - Date.parse(lka)) / 86400000) : null;
    const kind = classifyKind(a.os?.name ?? '', a.name);
    const { health, motivo } = classifyHealth(a.status, staleDays, kind);
    return {
      id: a.id, name: a.name, ip: a.ip ?? '—', status: a.status, os,
      version: a.version ?? '—', lastKeepAlive: a.lastKeepAlive ?? '—',
      kind, staleDays, health, motivo,
      needsAttention: health === 'fantasma' || health === 'investigar' || health === 'alerta',
    };
  });
  // Los que necesitan atención primero; luego activos; luego por nombre.
  const rank = (h: AgentHealth) => (h === 'fantasma' ? 0 : h === 'investigar' ? 1 : h === 'alerta' ? 2 : h === 'ok' ? 4 : 3);
  items.sort((x, y) => rank(x.health) - rank(y.health) || x.name.localeCompare(y.name));
  return items;
}

/** Elimina el registro de un agente Wazuh (depurar fantasmas/muertos). Nunca el 000 (manager). */
export async function removeAgent(agentId: string): Promise<void> {
  if (!/^\d{3,}$/.test(agentId) || agentId === '000') {
    throw new HttpError(400, 'ID de agente inválido');
  }
  // Wazuh 4.x: DELETE /agents con agents_list + status y older_than requeridos.
  await wazuhApiDelete('/agents', { agents_list: agentId, status: 'all', older_than: '0s' });
}

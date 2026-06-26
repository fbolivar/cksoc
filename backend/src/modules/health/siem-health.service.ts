/**
 * Salud del SIEM: vigila la propia plataforma Wazuh (agentes, manager, indexer,
 * disco y flujo de alertas). "Quien vigila al vigilante".
 * Calibrado al baseline real: en clusters de 1 nodo el estado 'yellow' es normal
 * (replicas sin asignar); los procesos opcionales del manager detenidos no alarman.
 */
import axios, { type AxiosInstance } from 'axios';
import https from 'node:https';
import { env } from '../../config/env';
import { wazuhApiGet } from '../wazuh/wazuh.api.client';
import { getIndexerClient } from '../wazuh/wazuh.client';

export type Estado = 'ok' | 'warn' | 'fail';

export interface HealthComponent {
  id: string;
  nombre: string;
  estado: Estado;
  resumen: string;
  detalle?: string;
}

export interface AgentHealth {
  id: string;
  name: string;
  status: string;
  lastKeepAlive: string | null;
  minutosSinReportar: number | null;
  estado: Estado;
}

export interface SiemHealth {
  semaforo: 'verde' | 'amarillo' | 'rojo';
  generadoEn: string;
  componentes: HealthComponent[];
  agentes: AgentHealth[];
}

let adminClient: AxiosInstance | null = null;
function indexerAdmin(): AxiosInstance | null {
  if (!env.INDEXER_ADMIN_USER || !env.INDEXER_ADMIN_PASS || !env.WAZUH_INDEXER_URL) return null;
  if (adminClient) return adminClient;
  adminClient = axios.create({
    baseURL: env.WAZUH_INDEXER_URL,
    auth: { username: env.INDEXER_ADMIN_USER, password: env.INDEXER_ADMIN_PASS },
    timeout: 8000,
    httpsAgent: new https.Agent({ rejectUnauthorized: env.WAZUH_TLS_REJECT_UNAUTHORIZED }),
  });
  return adminClient;
}

const worse = (a: Estado, b: Estado): Estado =>
  a === 'fail' || b === 'fail' ? 'fail' : a === 'warn' || b === 'warn' ? 'warn' : 'ok';

// ----------------- Agentes -----------------
export async function checkAgents(): Promise<{ comp: HealthComponent; agentes: AgentHealth[] }> {
  try {
    const data = await wazuhApiGet<{ affected_items: Array<{ id: string; name: string; status: string; lastKeepAlive?: string }> }>(
      '/agents', { select: 'id,name,status,lastKeepAlive', limit: 500, sort: 'id' }
    );
    const now = Date.now();
    const agentes: AgentHealth[] = data.affected_items
      .filter((a) => a.id !== '000') // 000 = el manager
      .map((a) => {
        const lka = a.lastKeepAlive && !a.lastKeepAlive.startsWith('9999') ? a.lastKeepAlive : null;
        const mins = lka ? Math.round((now - new Date(lka).getTime()) / 60000) : null;
        let estado: Estado = 'ok';
        if (a.status !== 'active') estado = 'fail';
        else if (mins != null && mins > env.HEALTH_AGENT_STALE_MIN) estado = 'warn';
        return { id: a.id, name: a.name, status: a.status, lastKeepAlive: lka, minutosSinReportar: mins, estado };
      });
    const activos = agentes.filter((a) => a.status === 'active').length;
    const estado = agentes.reduce<Estado>((acc, a) => worse(acc, a.estado), 'ok');
    const finalEstado = activos < env.HEALTH_EXPECTED_AGENTS ? 'fail' : estado;
    return {
      comp: {
        id: 'agentes', nombre: 'Agentes Wazuh', estado: finalEstado,
        resumen: `${activos}/${env.HEALTH_EXPECTED_AGENTS} activos`,
        detalle: agentes.filter((a) => a.estado !== 'ok').map((a) => `${a.name}: ${a.status}${a.minutosSinReportar != null ? ` (${a.minutosSinReportar} min)` : ''}`).join('; ') || undefined,
      },
      agentes,
    };
  } catch (err) {
    return { comp: { id: 'agentes', nombre: 'Agentes Wazuh', estado: 'fail', resumen: 'No se pudo consultar la API de Wazuh', detalle: errMsg(err) }, agentes: [] };
  }
}

// ----------------- Manager -----------------
export async function checkManager(): Promise<HealthComponent> {
  const critical = env.HEALTH_CRITICAL_PROCS.split(',').map((s) => s.trim());
  try {
    const data = await wazuhApiGet<{ affected_items: Record<string, string>[] }>('/manager/status');
    const procs = data.affected_items[0] ?? {};
    const detenidos = critical.filter((p) => procs[p] && procs[p] !== 'running');
    const faltantes = critical.filter((p) => !(p in procs));
    const malos = [...detenidos, ...faltantes.filter((p) => !(p in procs))];
    const running = critical.filter((p) => procs[p] === 'running').length;
    return {
      id: 'manager', nombre: 'Manager Wazuh',
      estado: detenidos.length > 0 ? 'fail' : 'ok',
      resumen: `${running}/${critical.length} procesos críticos activos`,
      detalle: detenidos.length ? `Detenidos: ${detenidos.join(', ')}` : (malos.length ? `Sin reportar: ${malos.join(', ')}` : undefined),
    };
  } catch (err) {
    return { id: 'manager', nombre: 'Manager Wazuh', estado: 'fail', resumen: 'No se pudo consultar el estado del manager', detalle: errMsg(err) };
  }
}

// ----------------- Indexer (cluster + disco) -----------------
export async function checkIndexer(): Promise<HealthComponent[]> {
  const client = indexerAdmin();
  if (!client) {
    return [{ id: 'indexer', nombre: 'Indexer (clúster)', estado: 'warn', resumen: 'Credenciales admin del Indexer no configuradas', detalle: 'Define INDEXER_ADMIN_USER/PASS para monitorear el clúster y el disco' }];
  }
  const comps: HealthComponent[] = [];
  // Cluster health
  try {
    const { data } = await client.get<{ status: string; number_of_nodes: number; unassigned_shards: number; active_shards: number }>('/_cluster/health');
    let estado: Estado = 'ok';
    let nota = '';
    if (data.status === 'red') estado = 'fail';
    else if (data.status === 'yellow') {
      // En cluster de 1 nodo, yellow (replicas sin asignar) es el estado normal.
      if (data.number_of_nodes <= 1) { estado = 'ok'; nota = ' (normal en clúster de un nodo)'; }
      else estado = 'warn';
    }
    comps.push({
      id: 'indexer', nombre: 'Indexer (clúster)', estado,
      resumen: `${data.status}${nota} · ${data.active_shards} shards`,
      detalle: data.unassigned_shards ? `${data.unassigned_shards} shards sin asignar` : undefined,
    });
  } catch (err) {
    comps.push({ id: 'indexer', nombre: 'Indexer (clúster)', estado: 'fail', resumen: 'No responde el clúster', detalle: errMsg(err) });
  }
  // Disco
  try {
    const { data } = await client.get<{ 'disk.percent': string | null; node: string }[]>('/_cat/allocation?format=json');
    const node = data.find((n) => n['disk.percent'] != null);
    const pct = node ? Number(node['disk.percent']) : null;
    let estado: Estado = 'ok';
    if (pct != null && pct >= env.HEALTH_DISK_CRIT) estado = 'fail';
    else if (pct != null && pct >= env.HEALTH_DISK_WARN) estado = 'warn';
    comps.push({
      id: 'disco', nombre: 'Disco del Indexer', estado,
      resumen: pct != null ? `${pct}% usado` : 'desconocido',
      detalle: pct != null && pct >= env.HEALTH_DISK_WARN ? `Por encima del umbral de ${estado === 'fail' ? env.HEALTH_DISK_CRIT : env.HEALTH_DISK_WARN}%` : undefined,
    });
  } catch (err) {
    comps.push({ id: 'disco', nombre: 'Disco del Indexer', estado: 'warn', resumen: 'No se pudo leer el disco', detalle: errMsg(err) });
  }
  return comps;
}

// ----------------- Flujo de alertas -----------------
export async function checkAlertFlow(): Promise<HealthComponent> {
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{ count: number }>(`/${env.WAZUH_ALERTS_INDEX}/_count`, {
      query: { range: { timestamp: { gte: `now-${env.HEALTH_ALERTFLOW_WINDOW_MIN}m` } } },
    });
    const estado: Estado = data.count < env.HEALTH_ALERTFLOW_MIN ? 'fail' : 'ok';
    return {
      id: 'flujo', nombre: 'Flujo de alertas', estado,
      resumen: `${data.count} alertas en ${env.HEALTH_ALERTFLOW_WINDOW_MIN} min`,
      detalle: estado === 'fail' ? 'Ingesta posiblemente detenida (sin eventos recientes)' : undefined,
    };
  } catch (err) {
    return { id: 'flujo', nombre: 'Flujo de alertas', estado: 'fail', resumen: 'No se pudo consultar el Indexer', detalle: errMsg(err) };
  }
}

// ----------------- Consolidado -----------------
export async function getOverallHealth(): Promise<SiemHealth> {
  const [ag, mgr, idx, flow] = await Promise.all([checkAgents(), checkManager(), checkIndexer(), checkAlertFlow()]);
  const componentes = [ag.comp, mgr, ...idx, flow];
  const peor = componentes.reduce<Estado>((acc, c) => worse(acc, c.estado), 'ok');
  return {
    semaforo: peor === 'fail' ? 'rojo' : peor === 'warn' ? 'amarillo' : 'verde',
    generadoEn: new Date().toISOString(),
    componentes,
    agentes: ag.agentes,
  };
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : 'error';
}

// Cache del ultimo estado (lo refresca el monitor; el panel lo lee sin recalcular).
let cached: SiemHealth | null = null;
export function cachedHealth(): SiemHealth | null {
  return cached;
}
export async function refreshHealth(): Promise<SiemHealth> {
  cached = await getOverallHealth();
  return cached;
}

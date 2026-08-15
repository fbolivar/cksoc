/**
 * Métricas por SEDE (ubicaciones GVM). Consolida señales reales:
 *  - agentes Wazuh mapeados a la sede por nombre (la mayoría en Bogotá/infra),
 *  - logins de las cuentas de esa sede en los eventos de autenticación (7d)
 *    — así las sedes regionales (Medellín, La Ceja, Entrerríos, Fómeque), que no
 *    tienen agente, sí muestran actividad real de sus usuarios.
 */
import { getAssetList } from '../assets/assets.service';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';

export interface SedeMetrics {
  name: string;
  region: string;
  rol?: string;
  agentes: number;
  agentesActivos: number;
  logins7d: number;
  usuarios: number;
  users: string[];        // cuentas de login de la sede (para filtrar el SOC)
  agentNames: string[];   // agentes mapeados a la sede
  ultimaActividad: string | null;
  estado: 'activa' | 'inactiva';
}

interface SedeDef { name: string; region: string; rol?: string; agentRe?: RegExp; userRe: RegExp }
const SEDES: SedeDef[] = [
  { name: 'Bogotá', region: 'Cundinamarca', rol: 'Principal', agentRe: /(gvmbog|gvm-soc|pmx-soc|gvmcorp)/i, userRe: /(gvmc|soporte|root|viviana|operaciones|gvm_?bog|admin)/i },
  { name: 'Medellín', region: 'Antioquia', userRe: /medellin/i },
  { name: 'La Ceja', region: 'Antioquia', userRe: /ceja/i },
  { name: 'Entrerríos', region: 'Antioquia', userRe: /entrerr/i },
  { name: 'Fómeque', region: 'Cundinamarca', userRe: /fomeque/i },
];

interface UBucket { key: string; doc_count: number; last: { value_as_string?: string } }

/** Agrega logins (auth_success 7d) por usuario, uniendo dos campos posibles. */
async function loginsByUser(): Promise<Map<string, { count: number; last: string | null }>> {
  const map = new Map<string, { count: number; last: string | null }>();
  try {
    const client = getIndexerClient();
    const { data } = await client.post<{ aggregations?: { uwin: { buckets: UBucket[] }; usrc: { buckets: UBucket[] } } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 0,
        query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-7d' } } }, { term: { 'rule.groups': 'authentication_success' } }] } },
        aggs: {
          uwin: { terms: { field: 'data.win.eventdata.targetUserName', size: 80 }, aggs: { last: { max: { field: '@timestamp' } } } },
          usrc: { terms: { field: 'data.srcuser', size: 80 }, aggs: { last: { max: { field: '@timestamp' } } } },
        },
      }
    );
    const merge = (buckets: UBucket[]) => {
      for (const b of buckets) {
        const k = String(b.key);
        const cur = map.get(k) ?? { count: 0, last: null };
        cur.count += b.doc_count;
        const l = b.last.value_as_string ?? null;
        if (l && (!cur.last || l > cur.last)) cur.last = l;
        map.set(k, cur);
      }
    };
    merge(data.aggregations?.uwin?.buckets ?? []);
    merge(data.aggregations?.usrc?.buckets ?? []);
  } catch { /* sin auth: se degrada a solo agentes */ }
  return map;
}

export async function getSedes(): Promise<SedeMetrics[]> {
  const [agentsR, users] = await Promise.all([getAssetList().catch(() => []), loginsByUser()]);
  const agents = agentsR;
  const userArr = [...users.entries()];

  return SEDES.map((s) => {
    const ags = s.agentRe ? agents.filter((a) => s.agentRe!.test(a.name)) : [];
    const agentesActivos = ags.filter((a) => a.status === 'active').length;
    const matched = userArr.filter(([u]) => s.userRe.test(u));
    const logins7d = matched.reduce((n, [, v]) => n + v.count, 0);
    const usuarios = matched.length;
    let ultimaActividad: string | null = null;
    for (const [, v] of matched) if (v.last && (!ultimaActividad || v.last > ultimaActividad)) ultimaActividad = v.last;
    const estado: 'activa' | 'inactiva' = agentesActivos > 0 || logins7d > 0 ? 'activa' : 'inactiva';
    return { name: s.name, region: s.region, rol: s.rol, agentes: ags.length, agentesActivos, logins7d, usuarios, users: matched.map(([u]) => u).slice(0, 15), agentNames: ags.map((a) => a.name), ultimaActividad, estado };
  });
}

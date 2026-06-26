/**
 * IT Hygiene: inventario de los endpoints (wazuh-states-inventory-*).
 * Vistas: sistema/hardware, puertos a la escucha (superficie de ataque),
 * software instalado, usuarios (con foco en cuentas de riesgo) y parches.
 */
import { getStatesClient } from '../wazuh/wazuh.client';

const I = (t: string) => `wazuh-states-inventory-${t}-*`;

interface Bucket { key: string; doc_count: number }

async function termsByAgent(index: string, query?: unknown): Promise<{ map: Map<string, number>; total: number }> {
  const client = getStatesClient();
  try {
    const { data } = await client.post<{
      hits: { total: { value: number } };
      aggregations: { ag: { buckets: Bucket[] } };
    }>(`/${index}/_search`, {
      size: 0,
      track_total_hits: true,
      ...(query ? { query } : {}),
      aggs: { ag: { terms: { field: 'agent.name', size: 50 } } },
    });
    return {
      map: new Map(data.aggregations.ag.buckets.map((b) => [b.key, b.doc_count])),
      total: data.hits.total.value,
    };
  } catch {
    return { map: new Map(), total: 0 };
  }
}

// ----------------- Resumen: sistema + hardware + conteos -----------------
export interface HostInfo {
  agent: string;
  hostname: string;
  os: string;
  arch: string;
  cpu: string;
  cores: number;
  ramGB: number;
  packages: number;
  ports: number;
  users: number;
  hotfixes: number;
}

export async function getSummary(): Promise<{ kpis: Record<string, number>; hosts: HostInfo[] }> {
  const client = getStatesClient();
  const listening = { term: { 'interface.state': 'listening' } };

  const [sys, hw, pkg, prt, usr, htf, prc] = await Promise.all([
    client.post<{ hits: { hits: { _source: Record<string, unknown> }[] } }>(`/${I('system')}/_search`, {
      size: 50, _source: ['agent.name', 'host.hostname', 'host.os.name', 'host.os.kernel.release', 'host.architecture'],
    }),
    client.post<{ hits: { hits: { _source: Record<string, unknown> }[] } }>(`/${I('hardware')}/_search`, {
      size: 50, _source: ['agent.name', 'host.cpu.name', 'host.cpu.cores', 'host.memory.total'],
    }),
    termsByAgent(I('packages')),
    termsByAgent(I('ports'), { bool: { filter: [listening] } }),
    termsByAgent(I('users')),
    termsByAgent(I('hotfixes')),
    termsByAgent(I('processes')),
  ]);

  const hw_by = new Map<string, { cpu: string; cores: number; ram: number }>();
  for (const h of hw.data.hits.hits) {
    const s = h._source as { agent?: { name?: string }; host?: { cpu?: { name?: string; cores?: number }; memory?: { total?: number } } };
    if (s.agent?.name) hw_by.set(s.agent.name, {
      cpu: s.host?.cpu?.name ?? '', cores: s.host?.cpu?.cores ?? 0, ram: s.host?.memory?.total ?? 0,
    });
  }

  const hosts: HostInfo[] = sys.data.hits.hits.map((h) => {
    const s = h._source as { agent?: { name?: string }; host?: { hostname?: string; architecture?: string; os?: { name?: string; kernel?: { release?: string } } } };
    const agent = s.agent?.name ?? '';
    const hwInfo = hw_by.get(agent);
    return {
      agent,
      hostname: s.host?.hostname ?? agent,
      os: s.host?.os?.name ?? '',
      arch: s.host?.architecture ?? '',
      cpu: hwInfo?.cpu ?? '',
      cores: hwInfo?.cores ?? 0,
      ramGB: hwInfo ? Math.round((hwInfo.ram / 1024 ** 3) * 10) / 10 : 0,
      packages: pkg.map.get(agent) ?? 0,
      ports: prt.map.get(agent) ?? 0,
      users: usr.map.get(agent) ?? 0,
      hotfixes: htf.map.get(agent) ?? 0,
    };
  });
  hosts.sort((a, b) => a.hostname.localeCompare(b.hostname));

  return {
    kpis: {
      hosts: hosts.length,
      packages: pkg.total,
      listening: prt.total,
      processes: prc.total,
      users: usr.total,
      hotfixes: htf.total,
    },
    hosts,
  };
}

// ----------------- Puertos a la escucha (superficie de ataque) -----------------
export interface PortRow { agent: string; port: number; transport: string; ip: string; process: string }

export async function getPorts(): Promise<PortRow[]> {
  const client = getStatesClient();
  try {
    const { data } = await client.post<{ hits: { hits: { _source: Record<string, unknown> }[] } }>(`/${I('ports')}/_search`, {
      size: 300,
      query: { bool: { filter: [{ term: { 'interface.state': 'listening' } }] } },
      _source: ['agent.name', 'source.ip', 'source.port', 'network.transport', 'process.name'],
      sort: [{ 'source.port': { order: 'asc' } }],
    });
    return data.hits.hits.map((h) => {
      const s = h._source as { agent?: { name?: string }; source?: { ip?: string; port?: number }; network?: { transport?: string }; process?: { name?: string } };
      return {
        agent: s.agent?.name ?? '',
        port: s.source?.port ?? 0,
        transport: s.network?.transport ?? '',
        ip: s.source?.ip ?? '',
        process: s.process?.name ?? '',
      };
    });
  } catch {
    return [];
  }
}

// ----------------- Software instalado -----------------
export interface SoftwareRow { name: string; vendor: string; hosts: number }

export async function getSoftware(): Promise<SoftwareRow[]> {
  const client = getStatesClient();
  try {
    const { data } = await client.post<{
      aggregations: { sw: { buckets: (Bucket & { v: { hits: { hits: { _source: Record<string, unknown> }[] } }; h: { value: number } })[] } };
    }>(`/${I('packages')}/_search`, {
      size: 0,
      aggs: {
        sw: {
          terms: { field: 'package.name', size: 60, order: { h: 'desc' } },
          aggs: { h: { cardinality: { field: 'agent.name' } }, v: { top_hits: { size: 1, _source: ['package.vendor'] } } },
        },
      },
    });
    return data.aggregations.sw.buckets.map((b) => {
      const src = b.v.hits.hits[0]?._source as { package?: { vendor?: string } } | undefined;
      return { name: b.key, vendor: src?.package?.vendor ?? '', hosts: b.h.value };
    });
  } catch {
    return [];
  }
}

// ----------------- Usuarios (foco en cuentas de riesgo) -----------------
export interface UserRow { agent: string; name: string; fullName: string; hidden: boolean; remote: boolean; groups: string[]; authFailures: number }

export async function getUsers(): Promise<{ porAgente: { agent: string; count: number }[]; riesgo: UserRow[] }> {
  const client = getStatesClient();
  const counts = await termsByAgent(I('users'));
  let riesgo: UserRow[] = [];
  try {
    const { data } = await client.post<{ hits: { hits: { _source: Record<string, unknown> }[] } }>(`/${I('users')}/_search`, {
      size: 100,
      query: {
        bool: {
          should: [
            { term: { 'user.is_hidden': true } },
            { range: { 'user.auth_failures.count': { gt: 0 } } },
          ],
          minimum_should_match: 1,
        },
      },
      _source: ['agent.name', 'user.name', 'user.full_name', 'user.is_hidden', 'user.is_remote', 'user.groups', 'user.auth_failures.count'],
    });
    riesgo = data.hits.hits.map((h) => {
      const s = h._source as { agent?: { name?: string }; user?: { name?: string; full_name?: string; is_hidden?: boolean; is_remote?: boolean; groups?: string[]; auth_failures?: { count?: number } } };
      return {
        agent: s.agent?.name ?? '',
        name: s.user?.name ?? '',
        fullName: s.user?.full_name ?? '',
        hidden: s.user?.is_hidden ?? false,
        remote: s.user?.is_remote ?? false,
        groups: s.user?.groups ?? [],
        authFailures: s.user?.auth_failures?.count ?? 0,
      };
    });
  } catch {
    /* sin datos */
  }
  return {
    porAgente: [...counts.map.entries()].map(([agent, count]) => ({ agent, count })).sort((a, b) => b.count - a.count),
    riesgo,
  };
}

// ----------------- Parches (hotfixes) -----------------
export async function getHotfixes(): Promise<{ agent: string; count: number; recientes: string[] }[]> {
  const client = getStatesClient();
  try {
    const { data } = await client.post<{
      aggregations: { ag: { buckets: (Bucket & { kb: { buckets: Bucket[] } })[] } };
    }>(`/${I('hotfixes')}/_search`, {
      size: 0,
      aggs: {
        ag: {
          terms: { field: 'agent.name', size: 50 },
          aggs: { kb: { terms: { field: 'package.hotfix.name', size: 5, order: { _key: 'desc' } } } },
        },
      },
    });
    return data.aggregations.ag.buckets.map((b) => ({
      agent: b.key,
      count: b.doc_count,
      recientes: b.kb.buckets.map((k) => k.key),
    }));
  } catch {
    return [];
  }
}

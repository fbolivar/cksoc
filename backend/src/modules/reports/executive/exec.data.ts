/**
 * Recopilacion de datos para el reporte ejecutivo mensual.
 * Agrega metricas del mes desde el Indexer de Wazuh y los modulos
 * (geo, respuesta). Calcula el semaforo de postura. Todo en datos crudos;
 * la traduccion a lenguaje ejecutivo ocurre en exec.template.
 */
import { getIndexerClient } from '../../wazuh/wazuh.client';
import { env } from '../../../config/env';
import { query } from '../../../config/db';
import { geolocate, isPublicIP } from '../../geo/geoip.service';
import { getAgentsSummary } from '../../wazuh/agents.service';
import { getVulnerabilities } from '../../vulnerabilities/vuln.service';
import { getSca } from '../../sca/sca.service';
import { getCompliance } from '../../compliance/compliance.service';

export interface ThreatOrigin { country: string; count: number; }
export interface BlockedIp { ip: string; motivo: string | null; fecha: string; }
export interface TrendPoint { mes: string; total: number; criticos: number; bloqueadas: number; }

export interface PosturaEndpoints {
  vulnTotal: number;
  vulnCriticas: number;
  vulnAltas: number;
  topCves: { cve: string; severity: string }[];
  hardeningScore: number;            // % promedio CIS
  hardeningPeor: { agent: string; score: number } | null;
  cumplimiento: { marco: string; controles: number }[]; // marcos regulatorios cubiertos
}

export interface ReportMetrics {
  mes: string;            // YYYY-MM
  periodoLabel: string;   // "junio de 2026"
  rangoTexto: string;     // "1 al 30 de junio de 2026"
  generadoEn: string;
  // Volumen / severidad
  totalEventos: number;
  criticos: number;       // nivel >= 12
  altos: number;          // nivel 8-11
  medios: number;         // nivel 5-7
  // Incidentes significativos
  bruteForceIntentos: number;
  bruteForceOrigenes: number;
  topAmenazas: { tipo: string; conteo: number }[];
  // Panorama
  origenes: ThreatOrigin[];
  // Acciones
  ipsBloqueadas: BlockedIp[];
  // Cobertura
  agentesActivos: number;
  agentesTotal: number;
  // Postura de endpoints (vulnerabilidades, hardening, cumplimiento)
  postura: PosturaEndpoints | null;
  // Tendencias
  semaforo: 'verde' | 'amarillo' | 'rojo';
  tendencia: TrendPoint[];
}

const MESES = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];

function monthBounds(mes: string): { gte: string; lt: string; periodoLabel: string; rangoTexto: string } {
  const [y, m] = mes.split('-').map(Number);
  const start = new Date(Date.UTC(y, m - 1, 1));
  const end = new Date(Date.UTC(y, m, 1)); // primer dia del mes siguiente
  const lastDay = new Date(Date.UTC(y, m, 0)).getUTCDate();
  return {
    gte: start.toISOString(),
    lt: end.toISOString(),
    periodoLabel: `${MESES[m - 1]} de ${y}`,
    rangoTexto: `1 al ${lastDay} de ${MESES[m - 1]} de ${y}`,
  };
}

export function currentMonth(): string {
  const n = new Date();
  return `${n.getUTCFullYear()}-${String(n.getUTCMonth() + 1).padStart(2, '0')}`;
}

export async function collectMetrics(mes: string): Promise<ReportMetrics> {
  const client = getIndexerClient();
  const { gte, lt, periodoLabel, rangoTexto } = monthBounds(mes);
  const idx = `/${env.WAZUH_ALERTS_INDEX}`;
  const timeFilter = { range: { timestamp: { gte, lt } } };

  // Reglas con falsos positivos conocidos a excluir del conteo de incidentes
  const excludeRules = env.REPORT_EXCLUDE_RULES.split(',').map((s) => s.trim()).filter(Boolean);
  const notNoise = excludeRules.length ? [{ bool: { must_not: [{ terms: { 'rule.id': excludeRules } }] } }] : [];

  const countWith = async (extra: unknown[]): Promise<number> => {
    const { data } = await client.post<{ count: number }>(`${idx}/_count`, {
      query: { bool: { filter: [timeFilter, ...extra] } },
    });
    return data.count;
  };

  // Volumen total (crudo) y severidad de INCIDENTES (excluyendo FP conocidos)
  const [totalEventos, criticos, altos, medios] = await Promise.all([
    countWith([]),
    countWith([{ range: { 'rule.level': { gte: 12 } } }, ...notNoise]),
    countWith([{ range: { 'rule.level': { gte: 8, lte: 11 } } }, ...notNoise]),
    countWith([{ range: { 'rule.level': { gte: 5, lte: 7 } } }, ...notNoise]),
  ]);

  // Fuerza bruta VPN (reglas configuradas)
  const bruteRules = env.NOTIFY_BRUTEFORCE_RULES.split(',').map((s) => s.trim());
  const bruteForceIntentos = await countWith([{ terms: { 'rule.id': bruteRules } }]).catch(() => 0);

  // Origenes de ataque (IP publica) agregados por pais + nº de origenes
  const { data: aggData } = await client.post<{
    aggregations: { remip: { buckets: { key: string }[] }; srcip: { buckets: { key: string }[] }; topr: { buckets: { key: string; doc_count: number }[] } };
  }>(`${idx}/_search`, {
    size: 0,
    query: { bool: { filter: [timeFilter, ...notNoise] } },
    aggs: {
      remip: { terms: { field: 'data.remip', size: 200 } },
      srcip: { terms: { field: 'data.srcip', size: 200 } },
      topr: { terms: { field: 'rule.description', size: 8 } },
    },
  });
  const publicIps = [...aggData.aggregations.remip.buckets, ...aggData.aggregations.srcip.buckets]
    .map((b) => b.key)
    .filter((ip) => isPublicIP(ip));
  const byCountry = new Map<string, number>();
  for (const ip of publicIps) {
    const g = geolocate(ip);
    if (!g) continue;
    byCountry.set(g.country, (byCountry.get(g.country) ?? 0) + 1);
  }
  const origenes = [...byCountry.entries()]
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  const bruteForceOrigenes = new Set(
    aggData.aggregations.remip.buckets.map((b) => b.key).filter(isPublicIP)
  ).size;

  // Top amenazas (descripciones de regla mas frecuentes con nivel relevante)
  const topAmenazas = aggData.aggregations.topr.buckets.map((b) => ({ tipo: b.key, conteo: b.doc_count }));

  // IPs bloqueadas en el mes (modulo respuesta)
  const blockedRows = await query<{ ip: string; motivo: string | null; created_at: string }>(
    `SELECT DISTINCT ON (ip) ip, motivo, created_at FROM block_actions
      WHERE accion='block' AND resultado='success' AND created_at >= $1 AND created_at < $2
      ORDER BY ip, created_at DESC`,
    [gte, lt]
  );
  const ipsBloqueadas = blockedRows.map((b) => ({ ip: b.ip, motivo: b.motivo, fecha: b.created_at }));

  // Cobertura de agentes (estado actual)
  const agents = await getAgentsSummary().catch(() => ({ active: 0, total: 0 }));

  // Postura de endpoints: vulnerabilidades, hardening (SCA) y cumplimiento.
  // Son estado ACTUAL de la plataforma (no acotado al mes), apropiado para el
  // informe de postura del comite. Tolerante a modulos sin datos.
  const [vuln, sca, comp] = await Promise.all([
    getVulnerabilities().catch(() => null),
    getSca().catch(() => null),
    getCompliance(720).catch(() => null),
  ]);
  let postura: PosturaEndpoints | null = null;
  if (vuln || sca || comp) {
    postura = {
      vulnTotal: vuln?.resumen.total ?? 0,
      vulnCriticas: vuln?.resumen.critical ?? 0,
      vulnAltas: vuln?.resumen.high ?? 0,
      topCves: (vuln?.topCve ?? []).slice(0, 5).map((c) => ({ cve: c.cve, severity: c.severity })),
      hardeningScore: sca?.resumen.scorePromedio ?? 0,
      hardeningPeor: sca?.agentes?.[0] ? { agent: sca.agentes[0].agent, score: sca.agentes[0].score } : null,
      cumplimiento: comp
        ? [
            { marco: 'NIST 800-53', controles: comp.frameworks.nist?.controles.length ?? 0 },
            { marco: 'GDPR', controles: comp.frameworks.gdpr?.controles.length ?? 0 },
            { marco: 'TSC (SOC 2)', controles: comp.frameworks.tsc?.controles.length ?? 0 },
          ]
        : [],
    };
  }

  // Tendencias: snapshots de meses anteriores
  const snaps = await query<{ mes: string; total_eventos: string; incidentes_criticos: number; ips_bloqueadas: number }>(
    `SELECT mes, total_eventos, incidentes_criticos, ips_bloqueadas FROM monthly_snapshots
      WHERE mes < $1 ORDER BY mes DESC LIMIT 5`,
    [mes]
  );
  const tendencia: TrendPoint[] = snaps
    .map((s) => ({ mes: s.mes, total: Number(s.total_eventos), criticos: s.incidentes_criticos, bloqueadas: s.ips_bloqueadas }))
    .reverse();

  // Semaforo de postura:
  //  ROJO    = actividad critica sostenida (>=5 eventos nivel>=12) -> atencion del comite
  //  AMARILLO= incidentes gestionados (fuerza bruta, bloqueos, o pocos criticos)
  //  VERDE   = operacion normal
  let semaforo: 'verde' | 'amarillo' | 'rojo' = 'verde';
  if (criticos >= 5) semaforo = 'rojo';
  else if (criticos > 0 || bruteForceIntentos > 0 || ipsBloqueadas.length > 0) semaforo = 'amarillo';

  return {
    mes, periodoLabel, rangoTexto, generadoEn: new Date().toISOString(),
    totalEventos, criticos, altos, medios,
    bruteForceIntentos, bruteForceOrigenes, topAmenazas,
    origenes, ipsBloqueadas,
    agentesActivos: agents.active, agentesTotal: agents.total,
    postura,
    semaforo, tendencia,
  };
}

/** Archiva el snapshot del mes (para tendencias futuras). */
export async function saveSnapshot(m: ReportMetrics): Promise<void> {
  await query(
    `INSERT INTO monthly_snapshots (mes, total_eventos, incidentes_criticos, incidentes_altos, ips_bloqueadas, top_amenazas, postura_semaforo, vuln_criticas, hardening_score)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
     ON CONFLICT (mes) DO UPDATE SET
       total_eventos=$2, incidentes_criticos=$3, incidentes_altos=$4,
       ips_bloqueadas=$5, top_amenazas=$6::jsonb, postura_semaforo=$7,
       vuln_criticas=$8, hardening_score=$9, generado_en=now()`,
    [m.mes, m.totalEventos, m.criticos, m.altos, m.ipsBloqueadas.length,
     JSON.stringify(m.topAmenazas.slice(0, 5)), m.semaforo,
     m.postura?.vulnCriticas ?? 0, m.postura?.hardeningScore ?? 0]
  );
}

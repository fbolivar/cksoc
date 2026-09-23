/**
 * Recopilacion de datos para el INFORME GERENCIAL de seguridad.
 *
 * Trabaja sobre un PERIODO arbitrario (ver periodo.ts) y ademas recopila el
 * periodo inmediatamente anterior de igual duracion para poder hacer analisis
 * comparativo (variaciones, tendencia).
 *
 * Aqui solo hay datos crudos y calculos. La traduccion a lenguaje de gestion
 * ocurre en exec.analysis.ts / exec.template.ts.
 */
import { getIndexerClient } from '../../wazuh/wazuh.client';
import { env } from '../../../config/env';
import { query } from '../../../config/db';
import { geolocate, isPublicIP } from '../../geo/geoip.service';
import { getAgentsSummary, socInfraMustNot, isSocInfra } from '../../wazuh/agents.service';
import { getVulnerabilities } from '../../vulnerabilities/vuln.service';
import { getSca } from '../../sca/sca.service';
import { getCompliance } from '../../compliance/compliance.service';
import { SLA_TARGETS, type Severity as SevIncidente } from '../../metrics/metrics.service';
import { resolvePeriodo, periodoAnterior, type Periodo } from './periodo';

export interface ThreatOrigin { country: string; count: number }
export interface BlockedIp { ip: string; motivo: string | null; fecha: string }
export interface SeriePunto { ts: string; total: number; criticos: number }
export interface SemanaResumen {
  etiqueta: string;                                   // "1 al 6 de julio"
  total: number;                                      // eventos de la semana
  equipoTop: string | null;                           // equipo con mas actividad
  diaPico: string | null;                             // dia con mas eventos (YYYY-MM-DD)
  topEquipos: { equipo: string; conteo: number }[];   // hasta 5, para el grafico
}
export interface TrendPoint { mes: string; total: number; criticos: number; bloqueadas: number }

export interface VolumenPeriodo {
  totalEventos: number;
  criticos: number;   // nivel >= 12
  altos: number;      // nivel 8-11
  medios: number;     // nivel 5-7
  bruteForceIntentos: number;
  ipsBloqueadas: number;
  incidentes: number;
}

export interface GestionIncidentes {
  total: number;
  porSeveridad: Record<SevIncidente, number>;
  resueltos: number;
  abiertos: number;
  tasaResolucion: number | null;     // % resueltos/cerrados sobre creados
  mttaMinutos: number | null;        // tiempo medio de primera atencion
  mttrMinutos: number | null;        // tiempo medio de resolucion
  cumplimientoSlaPct: number | null; // % que cumplio el tiempo de atencion comprometido
  masAntiguoAbiertoDias: number | null;
}

export interface PosturaEndpoints {
  vulnTotal: number;
  /** El indexador topa el conteo exacto en 10.000: si es asi, el total es un minimo. */
  vulnTotalAprox: boolean;
  vulnCriticas: number;
  vulnAltas: number;
  vulnKev: number;                                   // explotadas activamente (catalogo CISA KEV)
  equiposConVuln: number;
  topCves: { cve: string; severity: string; inKev: boolean }[];
  hardeningScore: number;                            // % promedio CIS
  hardeningPeor: { agent: string; score: number } | null;
  hardeningTopFallos: string[];
  cumplimiento: { marco: string; controles: number }[];
}

export interface ReportMetrics {
  // --- Identificacion del periodo ---
  periodo: Periodo;
  mes: string;               // compatibilidad (mes de inicio)
  periodoLabel: string;      // "junio de 2026"
  rangoTexto: string;        // "del 1 al 30 de junio de 2026"
  generadoEn: string;

  // --- Volumen y severidad ---
  totalEventos: number;
  criticos: number;
  altos: number;
  medios: number;

  // --- Comparativo con el periodo anterior de igual duracion ---
  anterior: (VolumenPeriodo & { label: string; rangoTexto: string }) | null;
  variacion: {
    totalEventos: number | null;   // % de cambio
    criticos: number | null;
    altos: number | null;
    ipsBloqueadas: number | null;
  };

  // --- Serie temporal dentro del periodo ---
  serie: SeriePunto[];

  // --- Actividad por semana (equipos mas activos de cada semana) ---
  actividadSemanal: SemanaResumen[];

  // --- Novedades detectadas (agentes nuevos en el periodo) ---
  novedades: string[];

  // --- Incidentes significativos ---
  bruteForceIntentos: number;
  bruteForceOrigenes: number;
  topAmenazas: { tipo: string; conteo: number }[];
  equiposMasAfectados: { equipo: string; conteo: number }[];

  // --- Panorama externo ---
  origenes: ThreatOrigin[];
  ipsUnicasExternas: number;

  // --- Acciones y gestion ---
  ipsBloqueadas: BlockedIp[];
  gestion: GestionIncidentes;

  // --- Cobertura ---
  agentesActivos: number;
  agentesTotal: number;
  agentesDesconectados: number;
  coberturaPct: number;

  // --- Postura ---
  postura: PosturaEndpoints | null;

  // --- Semaforo y tendencia historica ---
  semaforo: 'verde' | 'amarillo' | 'rojo';
  tendencia: TrendPoint[];
}

// --------------------------------------------------------------------------

/** Mes actual YYYY-MM (compatibilidad con el flujo anterior). */
export function currentMonth(): string {
  const n = new Date();
  return `${n.getUTCFullYear()}-${String(n.getUTCMonth() + 1).padStart(2, '0')}`;
}

function pctCambio(actual: number, previo: number): number | null {
  if (previo === 0) return actual === 0 ? 0 : null; // sin base de comparacion
  return Math.round(((actual - previo) / previo) * 100);
}

function promedio(xs: number[]): number | null {
  // Sin redondear: el formateo decide como presentarlo (ver duracionTexto).
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
}

function minutosEntre(desde: string, hasta: string): number {
  return (new Date(hasta).getTime() - new Date(desde).getTime()) / 60_000;
}

// --------------------------------------------------------------------------
// Consultas al Indexer
// --------------------------------------------------------------------------

// Exclusión de ruido benigno CONSISTENTE con los dashboards afinados: sin esto el
// informe inflaba ~65% las severidades (contaba el 100600 benigno interno/DVR/HexDesk
// + churn de bajo nivel que los paneles ya ocultan). El "total de eventos" NO usa esto
// (es throughput). Las severidades sí, para que el informe cuente la misma verdad.
function reglasExcluidas(): unknown[] {
  const envIds = env.REPORT_EXCLUDE_RULES.split(',').map((s) => s.trim()).filter(Boolean);
  const noiseRuleIds = ['81633', '80792', '550', '752', '91578', '100205', '100207', '100700', '5501', ...envIds]; // Forti app-passed, audit systemd, FIM checksum, registry, O365 MailItemsAccessed
  return [{
    bool: {
      must_not: [
        ...socInfraMustNot(), // no contar la infra del SOC (cs-soc-*, pmx-soc, gvm-soc) en el reporte del cliente
        { terms: { 'rule.id': noiseRuleIds } },
        { terms: { 'rule.groups': ['sca', 'vulnerability-detector'] } },
        // 100600 benigno: exfil interna (egress RFC1918), DVR (srcip) y relays HexDesk. El externo real se conserva.
        {
          bool: {
            filter: [
              { term: { 'rule.id': '100600' } },
              {
                bool: {
                  should: [
                    { prefix: { 'data.dstip': '192.168.' } },
                    { prefix: { 'data.dstip': '10.' } },
                    { prefix: { 'data.dstip': '172.' } },
                    { terms: { 'data.dstip': ['40.160.225.24', '209.250.254.15'] } },
                    { term: { 'data.srcip': '192.168.0.31' } },
                  ],
                  minimum_should_match: 1,
                },
              },
            ],
          },
        },
      ],
    },
  }];
}

/** Conteos de volumen de un periodo (usado tambien para el periodo anterior). */
async function volumenDe(p: Periodo): Promise<VolumenPeriodo> {
  const client = getIndexerClient();
  const idx = `/${env.WAZUH_ALERTS_INDEX}`;
  const timeFilter = { range: { timestamp: { gte: p.gte, lt: p.lt } } };
  const notNoise = reglasExcluidas();

  const countWith = async (extra: unknown[]): Promise<number> => {
    const { data } = await client.post<{ count: number }>(`${idx}/_count`, {
      query: { bool: { filter: [timeFilter, ...extra] } },
    });
    return data.count;
  };

  const bruteRules = env.NOTIFY_BRUTEFORCE_RULES.split(',').map((s) => s.trim()).filter(Boolean);

  const [totalEventos, criticos, altos, medios, bruteForceIntentos] = await Promise.all([
    countWith([]).catch(() => 0),
    countWith([{ range: { 'rule.level': { gte: 12 } } }, ...notNoise]).catch(() => 0),
    countWith([{ range: { 'rule.level': { gte: 8, lte: 11 } } }, ...notNoise]).catch(() => 0),
    countWith([{ range: { 'rule.level': { gte: 5, lte: 7 } } }, ...notNoise]).catch(() => 0),
    bruteRules.length ? countWith([{ terms: { 'rule.id': bruteRules } }]).catch(() => 0) : Promise.resolve(0),
  ]);

  const [{ n: ipsBloqueadas }] = await query<{ n: string }>(
    `SELECT COUNT(DISTINCT ip)::text AS n FROM block_actions
      WHERE accion='block' AND resultado='success' AND created_at >= $1 AND created_at < $2`,
    [p.gte, p.lt]
  ).then((r) => (r.length ? r : [{ n: '0' }])).catch(() => [{ n: '0' }]);

  const [{ n: incidentes }] = await query<{ n: string }>(
    `SELECT COUNT(*)::text AS n FROM incidents WHERE created_at >= $1 AND created_at < $2`,
    [p.gte, p.lt]
  ).then((r) => (r.length ? r : [{ n: '0' }])).catch(() => [{ n: '0' }]);

  return {
    totalEventos, criticos, altos, medios, bruteForceIntentos,
    ipsBloqueadas: Number(ipsBloqueadas), incidentes: Number(incidentes),
  };
}

/** Serie temporal de eventos (total y criticos) dentro del periodo. */
async function serieDe(p: Periodo): Promise<SeriePunto[]> {
  const client = getIndexerClient();
  const interval =
    p.granularidad === 'hora' ? '1h'
    : p.granularidad === 'dia' ? '1d'
    : p.granularidad === 'semana' ? '1w'
    : '1M';
  try {
    // calendar_interval + time_zone: los "días" son días de Colombia, no UTC.
    // extended_bounds asegura que la serie cubra TODO el periodo aunque haya
    // tramos sin datos (si no, el histograma arranca en el primer documento).
    const { data } = await client.post<{
      aggregations: {
        porFecha: { buckets: { key_as_string: string; doc_count: number; criticos: { doc_count: number } }[] };
      };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { bool: { filter: [{ range: { timestamp: { gte: p.gte, lt: p.lt } } }] } },
      aggs: {
        porFecha: {
          date_histogram: {
            field: 'timestamp',
            calendar_interval: interval,
            time_zone: 'America/Bogota',
            min_doc_count: 0,
            // `lt` es exclusivo: restar 1 ms evita un bucket final vacio.
            extended_bounds: { min: p.gte, max: new Date(new Date(p.lt).getTime() - 1).toISOString() },
          },
          aggs: { criticos: { filter: { range: { 'rule.level': { gte: 12 } } } } },
        },
      },
    });
    return data.aggregations.porFecha.buckets.map((b) => ({
      ts: b.key_as_string,
      total: b.doc_count,
      criticos: b.criticos?.doc_count ?? 0,
    }));
  } catch {
    return [];
  }
}

const MESES_DL = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];

/** Fecha ISO -> {y,m,d} local Colombia. */
function localYmd(iso: string): { y: number; m: number; d: number } {
  const t = new Date(new Date(iso).getTime() - 5 * 3600_000);
  return { y: t.getUTCFullYear(), m: t.getUTCMonth(), d: t.getUTCDate() };
}

/**
 * Actividad por semana calendario dentro del periodo: para cada semana, el
 * total de eventos, el equipo mas activo, el dia pico y el top de equipos.
 * Solo tiene sentido en periodos de varios dias; para ventanas por horas o de
 * pocos dias se devuelve vacio (el informe lo omite).
 */
async function actividadSemanalDe(p: Periodo): Promise<SemanaResumen[]> {
  if (p.granularidad === 'hora' || p.dias < 8) return [];
  const client = getIndexerClient();
  try {
    const { data } = await client.post<{
      aggregations: {
        semanas: {
          buckets: {
            key_as_string: string;
            doc_count: number;
            equipos: { buckets: { key: string; doc_count: number }[] };
            dias: { buckets: { key_as_string: string; doc_count: number }[] };
          }[];
        };
      };
    }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { bool: { filter: [{ range: { timestamp: { gte: p.gte, lt: p.lt } } }] } },
      aggs: {
        semanas: {
          date_histogram: {
            field: 'timestamp',
            calendar_interval: 'week',
            time_zone: 'America/Bogota',
            min_doc_count: 1,
          },
          aggs: {
            equipos: { terms: { field: 'agent.name', size: 5 } },
            dias: {
              date_histogram: { field: 'timestamp', calendar_interval: 'day', time_zone: 'America/Bogota', min_doc_count: 1 },
            },
          },
        },
      },
    });
    return data.aggregations.semanas.buckets.map((s, i, arr) => {
      // Etiqueta: rango de dias de la semana acotado al periodo
      const ini = localYmd(s.key_as_string);
      const finIso = i + 1 < arr.length ? arr[i + 1].key_as_string : p.lt;
      const finT = new Date(new Date(finIso).getTime() - 5 * 3600_000 - 86_400_000);
      const fin = { y: finT.getUTCFullYear(), m: finT.getUTCMonth(), d: finT.getUTCDate() };
      const etiqueta = ini.m === fin.m
        ? `${ini.d} al ${fin.d} de ${MESES_DL[ini.m]}`
        : `${ini.d} de ${MESES_DL[ini.m]} al ${fin.d} de ${MESES_DL[fin.m]}`;
      const top = s.equipos.buckets.map((b) => ({ equipo: b.key, conteo: b.doc_count }));
      const diaPico = [...s.dias.buckets].sort((a, b) => b.doc_count - a.doc_count)[0];
      return {
        etiqueta,
        total: s.doc_count,
        equipoTop: top[0]?.equipo ?? null,
        diaPico: diaPico ? localYmdStr(diaPico.key_as_string) : null,
        topEquipos: top,
      };
    });
  } catch {
    return [];
  }
}

function localYmdStr(iso: string): string {
  const { y, m, d } = localYmd(iso);
  return `${d} de ${MESES_DL[m]}`;
}

/**
 * Novedades por defecto: equipos que reportaron por PRIMERA vez en el periodo
 * (aparecen dentro de la ventana pero no en los 90 dias previos). Detecta altas
 * de monitoreo sin depender de la API de Wazuh.
 */
async function novedadesDe(p: Periodo): Promise<string[]> {
  const client = getIndexerClient();
  const idx = `/${env.WAZUH_ALERTS_INDEX}`;
  try {
    const listar = async (gte: string, lt: string): Promise<Set<string>> => {
      const { data } = await client.post<{ aggregations: { a: { buckets: { key: string }[] } } }>(
        `${idx}/_search`,
        { size: 0, query: { range: { timestamp: { gte, lt } } }, aggs: { a: { terms: { field: 'agent.name', size: 500 } } } }
      );
      return new Set(data.aggregations.a.buckets.map((b) => b.key));
    };
    const prevGte = new Date(new Date(p.gte).getTime() - 90 * 86_400_000).toISOString();
    const [enPeriodo, previos] = await Promise.all([
      listar(p.gte, p.lt),
      listar(prevGte, p.gte),
    ]);
    // Sin linea base previa (p.ej. el SIEM aun no tiene 90 dias de historia)
    // TODO equipo pareceria "nuevo": no se puede distinguir, se omite.
    if (previos.size === 0) return [];
    const nuevos = [...enPeriodo].filter((a) => !previos.has(a) && a !== '000' && !/manager/i.test(a));
    // Salvaguarda: si "casi todos" son nuevos, es un artefacto de historia
    // incompleta, no altas reales -> no reportar.
    if (nuevos.length > enPeriodo.size * 0.5) return [];
    return nuevos.map((a) => `El equipo ${a} se incorporó al monitoreo durante el periodo.`);
  } catch {
    return [];
  }
}

/** Gestion de incidentes (casos) creados dentro del periodo. */
async function gestionDe(p: Periodo): Promise<GestionIncidentes> {
  const vacio: GestionIncidentes = {
    total: 0,
    porSeveridad: { baja: 0, media: 0, alta: 0, critica: 0 },
    resueltos: 0, abiertos: 0, tasaResolucion: null,
    mttaMinutos: null, mttrMinutos: null, cumplimientoSlaPct: null,
    masAntiguoAbiertoDias: null,
  };
  const rows = await query<{
    id: string; severity: SevIncidente; status: string;
    created_at: string; closed_at: string | null; first_action: string | null;
  }>(
    `SELECT i.id, i.severity, i.status, i.created_at, i.closed_at,
            (SELECT min(n.created_at) FROM incident_notes n
               WHERE n.incident_id = i.id AND n.note NOT ILIKE 'Incidente creado%') AS first_action
       FROM incidents i
      WHERE i.created_at >= $1 AND i.created_at < $2`,
    [p.gte, p.lt]
  ).catch(() => []);
  if (rows.length === 0) return vacio;

  const out = { ...vacio, porSeveridad: { baja: 0, media: 0, alta: 0, critica: 0 } };
  const mtta: number[] = [];
  const mttr: number[] = [];
  let slaEvaluados = 0;
  let slaCumplidos = 0;
  let masAntiguo: number | null = null;
  const ahora = Date.now();

  for (const r of rows) {
    out.total++;
    if (r.severity in out.porSeveridad) out.porSeveridad[r.severity]++;
    const cerrado = r.status === 'resuelto' || r.status === 'cerrado';
    if (cerrado) out.resueltos++;
    else {
      out.abiertos++;
      const dias = (ahora - new Date(r.created_at).getTime()) / 86_400_000;
      masAntiguo = masAntiguo === null ? dias : Math.max(masAntiguo, dias);
    }
    if (r.first_action) {
      const d = minutosEntre(r.created_at, r.first_action);
      if (d >= 0) {
        mtta.push(d);
        slaEvaluados++;
        const objetivo = (SLA_TARGETS[r.severity] ?? SLA_TARGETS.media).responseMin;
        if (d <= objetivo) slaCumplidos++;
      }
    }
    if (cerrado && r.closed_at) {
      // Se ignoran los cierres instantaneos (mismo timestamp de creacion):
      // corresponden a cargas o depuraciones, no a una atencion real, y
      // hundirian artificialmente el tiempo medio de resolucion.
      const d = minutosEntre(r.created_at, r.closed_at);
      if (d > 0) mttr.push(d);
    }
  }

  out.tasaResolucion = out.total ? Math.round((out.resueltos / out.total) * 100) : null;
  out.mttaMinutos = promedio(mtta);
  out.mttrMinutos = promedio(mttr);
  out.cumplimientoSlaPct = slaEvaluados ? Math.round((slaCumplidos / slaEvaluados) * 100) : null;
  out.masAntiguoAbiertoDias = masAntiguo === null ? null : Math.round(masAntiguo);
  return out;
}

// --------------------------------------------------------------------------
// Recoleccion principal
// --------------------------------------------------------------------------

export async function collectMetrics(entrada: Periodo | string): Promise<ReportMetrics> {
  // Compatibilidad: si llega "YYYY-MM" se interpreta como ese mes completo.
  const p: Periodo =
    typeof entrada === 'string'
      ? mesComoPeriodo(entrada)
      : entrada;

  const client = getIndexerClient();
  const idx = `/${env.WAZUH_ALERTS_INDEX}`;
  const timeFilter = { range: { timestamp: { gte: p.gte, lt: p.lt } } };
  const notNoise = reglasExcluidas();
  const prev = periodoAnterior(p);

  const [volumen, volumenPrev, serie, gestion, actividadSemanal, novedades] = await Promise.all([
    volumenDe(p),
    volumenDe(prev).catch(() => null),
    serieDe(p),
    gestionDe(p),
    actividadSemanalDe(p),
    novedadesDe(p),
  ]);

  // Agregaciones de panorama: origenes, amenazas y equipos afectados
  let origenes: ThreatOrigin[] = [];
  let ipsUnicasExternas = 0;
  let bruteForceOrigenes = 0;
  let topAmenazas: { tipo: string; conteo: number }[] = [];
  let equiposMasAfectados: { equipo: string; conteo: number }[] = [];
  try {
    const { data: aggData } = await client.post<{
      aggregations: {
        remip: { buckets: { key: string }[] };
        srcip: { buckets: { key: string }[] };
        topr: { d: { buckets: { key: string; doc_count: number }[] } };
        agente: { buckets: { key: string; doc_count: number }[] };
      };
    }>(`${idx}/_search`, {
      size: 0,
      query: { bool: { filter: [timeFilter, ...notNoise] } },
      aggs: {
        remip: { terms: { field: 'data.remip', size: 200 } },
        srcip: { terms: { field: 'data.srcip', size: 200 } },
        topr: { filter: { range: { 'rule.level': { gte: 7 } } }, aggs: { d: { terms: { field: 'rule.description', size: 8 } } } },
        agente: { terms: { field: 'agent.name', size: 8 } },
      },
    });
    const publicIps = [...aggData.aggregations.remip.buckets, ...aggData.aggregations.srcip.buckets]
      .map((b) => b.key)
      .filter((ip) => isPublicIP(ip));
    ipsUnicasExternas = new Set(publicIps).size;
    const byCountry = new Map<string, number>();
    for (const ip of publicIps) {
      const g = geolocate(ip);
      if (!g) continue;
      byCountry.set(g.country, (byCountry.get(g.country) ?? 0) + 1);
    }
    origenes = [...byCountry.entries()]
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
    bruteForceOrigenes = new Set(
      aggData.aggregations.remip.buckets.map((b) => b.key).filter(isPublicIP)
    ).size;
    topAmenazas = aggData.aggregations.topr.d.buckets.map((b) => ({ tipo: b.key, conteo: b.doc_count }));
    equiposMasAfectados = aggData.aggregations.agente.buckets.map((b) => ({ equipo: b.key, conteo: b.doc_count }));
  } catch {
    /* el informe se genera igual, sin panorama externo */
  }

  // Bloqueos aplicados en el periodo
  const blockedRows = await query<{ ip: string; motivo: string | null; created_at: string }>(
    `SELECT DISTINCT ON (ip) ip, motivo, created_at FROM block_actions
      WHERE accion='block' AND resultado='success' AND created_at >= $1 AND created_at < $2
      ORDER BY ip, created_at DESC`,
    [p.gte, p.lt]
  ).catch(() => []);
  const ipsBloqueadas = blockedRows.map((b) => ({ ip: b.ip, motivo: b.motivo, fecha: b.created_at }));

  // Cobertura de monitoreo (estado actual)
  const agents = await getAgentsSummary().catch(
    () => ({ active: 0, total: 0, disconnected: 0, neverConnected: 0, pending: 0 })
  );
  const coberturaPct = agents.total ? Math.round((agents.active / agents.total) * 100) : 0;

  // Postura: vulnerabilidades, hardening y marcos regulatorios (estado actual)
  const [vuln, sca, comp] = await Promise.all([
    getVulnerabilities().catch(() => null),
    getSca().catch(() => null),
    getCompliance(720).catch(() => null),
  ]);
  // Vulnerabilidades SOLO de equipos del cliente (excluye la infra del SOC: cs-soc-*, etc.)
  const vulnCliente = (vuln?.porAgente ?? []).filter((a) => !isSocInfra(a.agent));
  const vCrit = vulnCliente.reduce((n, a) => n + (a.critical ?? 0), 0);
  const vHigh = vulnCliente.reduce((n, a) => n + (a.high ?? 0), 0);
  const vTotal = vulnCliente.reduce((n, a) => n + (a.total ?? 0), 0);
  let postura: PosturaEndpoints | null = null;
  if (vuln || sca || comp) {
    postura = {
      vulnTotal: vTotal,
      vulnTotalAprox: vTotal >= 10_000,
      vulnCriticas: vCrit,
      vulnAltas: vHigh,
      vulnKev: vuln?.resumen.kev ?? 0,
      equiposConVuln: vulnCliente.filter((a) => (a.total ?? 0) > 0).length,
      topCves: (vuln?.topCve ?? []).slice(0, 5).map((c) => ({
        cve: c.cve, severity: c.severity, inKev: Boolean(c.inKev),
      })),
      hardeningScore: sca?.resumen.scorePromedio ?? 0,
      hardeningPeor: sca?.agentes?.[0] ? { agent: sca.agentes[0].agent, score: sca.agentes[0].score } : null,
      hardeningTopFallos: (sca?.topFallidos ?? []).slice(0, 4).map((f) => String((f as { title?: string }).title ?? '')).filter(Boolean),
      cumplimiento: comp
        ? [
            { marco: 'NIST 800-53', controles: comp.frameworks.nist?.controles.length ?? 0 },
            { marco: 'GDPR', controles: comp.frameworks.gdpr?.controles.length ?? 0 },
            { marco: 'TSC (SOC 2)', controles: comp.frameworks.tsc?.controles.length ?? 0 },
          ]
        : [],
    };
  }

  // Tendencia historica (snapshots mensuales previos)
  const snaps = await query<{ mes: string; total_eventos: string; incidentes_criticos: number; ips_bloqueadas: number }>(
    `SELECT mes, total_eventos, incidentes_criticos, ips_bloqueadas FROM monthly_snapshots
      WHERE mes < $1 ORDER BY mes DESC LIMIT 6`,
    [p.mes]
  ).catch(() => []);
  const tendencia: TrendPoint[] = snaps
    .map((s) => ({ mes: s.mes, total: Number(s.total_eventos), criticos: s.incidentes_criticos, bloqueadas: s.ips_bloqueadas }))
    .reverse();

  // Semaforo de postura de gestion
  let semaforo: 'verde' | 'amarillo' | 'rojo' = 'verde';
  const criticasSinAtender = (postura?.vulnKev ?? 0) > 0 || (postura?.vulnCriticas ?? 0) >= 5;
  if (volumen.criticos >= 5 || criticasSinAtender || (gestion.masAntiguoAbiertoDias ?? 0) > 15) semaforo = 'rojo';
  else if (
    volumen.criticos > 0 || volumen.bruteForceIntentos > 0 || ipsBloqueadas.length > 0 ||
    (postura?.vulnAltas ?? 0) > 0 || coberturaPct < 100
  ) semaforo = 'amarillo';

  return {
    periodo: p,
    mes: p.mes,
    periodoLabel: p.label,
    rangoTexto: p.rangoTexto,
    generadoEn: new Date().toISOString(),

    totalEventos: volumen.totalEventos,
    criticos: volumen.criticos,
    altos: volumen.altos,
    medios: volumen.medios,

    anterior: volumenPrev ? { ...volumenPrev, label: prev.label, rangoTexto: prev.rangoTexto } : null,
    variacion: {
      totalEventos: volumenPrev ? pctCambio(volumen.totalEventos, volumenPrev.totalEventos) : null,
      criticos: volumenPrev ? pctCambio(volumen.criticos, volumenPrev.criticos) : null,
      altos: volumenPrev ? pctCambio(volumen.altos, volumenPrev.altos) : null,
      ipsBloqueadas: volumenPrev ? pctCambio(ipsBloqueadas.length, volumenPrev.ipsBloqueadas) : null,
    },

    serie,
    actividadSemanal,
    novedades,

    bruteForceIntentos: volumen.bruteForceIntentos,
    bruteForceOrigenes,
    topAmenazas,
    equiposMasAfectados,

    origenes,
    ipsUnicasExternas,

    ipsBloqueadas,
    gestion,

    agentesActivos: agents.active,
    agentesTotal: agents.total,
    agentesDesconectados: agents.disconnected ?? 0,
    coberturaPct,

    postura,
    semaforo,
    tendencia,
  };
}

/** Convierte "YYYY-MM" en el periodo del mes completo (compatibilidad). */
function mesComoPeriodo(mes: string): Periodo {
  const [y, m] = mes.split('-').map(Number);
  const fin = new Date(Date.UTC(y, m, 0)).getUTCDate();
  return resolvePeriodo({
    preset: 'personalizado',
    desde: `${mes}-01`,
    hasta: `${mes}-${String(fin).padStart(2, '0')}`,
  });
}

/**
 * Archiva el snapshot MENSUAL del periodo (solo cuando el periodo es un mes
 * calendario completo; para rangos libres no tiene sentido sobrescribirlo).
 */
export async function saveSnapshot(m: ReportMetrics): Promise<void> {
  const p = m.periodo;
  const esMesCompleto = /-01$/.test(p.desde) && p.desde.slice(0, 7) === p.hasta.slice(0, 7) && p.dias >= 28;
  if (!esMesCompleto) return;
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

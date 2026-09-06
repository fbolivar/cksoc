/**
 * Recoleccion de telemetria para el INFORME TECNICO del SOC.
 *
 * A diferencia del informe gerencial, aqui interesa el detalle accionable:
 * reglas concretas, hosts, usuarios, IPs, CVE, tecnicas ATT&CK y las consultas
 * que permiten reproducir cada hallazgo.
 *
 * Todo lo que depende del periodo se consulta acotado a la ventana exacta.
 * Lo que es "estado actual" de la plataforma (inventario, vulnerabilidades,
 * hardening, cobertura) se marca como tal en el informe.
 */
import { getIndexerClient } from '../../wazuh/wazuh.client';
import { env } from '../../../config/env';
import { query } from '../../../config/db';
import { geolocate, isPublicIP } from '../../geo/geoip.service';
import { getAgents, getAgentsSummary, type AgentItem } from '../../wazuh/agents.service';
import { getVulnerabilities, type VulnData } from '../../vulnerabilities/vuln.service';
import { getSca, type ScaData } from '../../sca/sca.service';
import { getCoverage, type CoverageData } from '../../mitre/mitre.service';
import { getPorts, getUsers, type PortRow, type UserRow } from '../../hygiene/hygiene.service';
import { listSuppressions, getCustomRules, type Suppression } from '../../detection/detection.service';
import { getMatches, type IocMatch } from '../../threatintel/threatintel.service';
import { SLA_TARGETS, type Severity as SevIncidente } from '../../metrics/metrics.service';
import { type Periodo, periodoAnterior } from '../executive/periodo';

// --------------------------------------------------------------------------
// Tipos
// --------------------------------------------------------------------------

export interface SeriePunto { ts: string; total: number; criticos: number }

export interface ReglaTop {
  ruleId: string;
  descripcion: string;
  nivel: number;
  grupos: string[];
  conteo: number;
  pctVolumen: number;
  agentes: number;
  mitre: string[];
}

export interface AgenteTop {
  agente: string;
  total: number;
  criticos: number;
  altos: number;
  reglasDistintas: number;
}

export interface TecnicaMitre {
  id: string;
  nombre: string;
  tacticas: string[];
  conteo: number;
  nivelMax: number;
}

export interface IpExterna {
  ip: string;
  pais: string | null;
  conteo: number;
  nivelMax: number;
  reglasDistintas: number;
  agentes: string[];
  primeraVez: string;
  ultimaVez: string;
  reglaEjemplo: string;
}

export interface Autenticacion {
  fallos: number;
  exitos: number;
  ratioFallo: number | null;      // fallos / (fallos + exitos)
  usuariosAtacados: { usuario: string; fallos: number }[];
  ipsOrigen: { ip: string; publica: boolean; pais: string | null; fallos: number }[];
  usuariosConExito: { usuario: string; exitos: number }[];
}

export interface CambioFim {
  ruta: string;
  evento: string;
  agente: string;
  usuario: string;
  nivel: number;
  ts: string;
  critico: boolean;               // ruta sensible (passwd, sudoers, binarios...)
}

export interface GestionIncidentes {
  total: number;
  porSeveridad: Record<SevIncidente, number>;
  porEstado: Record<string, number>;
  resueltos: number;
  abiertos: number;
  mttaMinutos: number | null;
  mttrMinutos: number | null;
  cumplimientoSlaPct: number | null;
  incumplidos: { id: string; titulo: string; severidad: string; minutos: number; objetivo: number }[];
  antiguos: { id: string; titulo: string; severidad: string; dias: number }[];
}

export interface AnomaliaUeba {
  detector: string; entidad: string; severidad: string; score: number;
  titulo: string; estado: string; ts: string;
}

export interface BloqueoAplicado { ip: string; motivo: string | null; ts: string; pais: string | null }

export interface SaludTelemetria {
  bucketsVacios: number;          // tramos sin un solo evento
  bucketsTotales: number;
  mayorHueco: { desde: string; horas: number } | null;
  agentesSinEventos: string[];    // agentes activos que no reportaron nada
  agentesDesconectados: { agente: string; ultimoContacto: string }[];
  versionesAgente: { version: string; agentes: number }[];
}

export interface TechMetrics {
  periodo: Periodo;
  generadoEn: string;
  titulo: string;

  // Volumen
  total: number;
  porNivel: { banda: string; rango: string; conteo: number }[];
  criticos: number;
  altos: number;
  medios: number;
  bajos: number;
  anterior: { total: number; criticos: number } | null;
  variacion: { total: number | null; criticos: number | null };

  // Serie y picos
  serie: SeriePunto[];
  picos: { ts: string; total: number; vecesMedia: number }[];

  // Detecciones
  topReglas: ReglaTop[];
  topAgentes: AgenteTop[];
  reglasDistintas: number;

  // Dominios
  mitre: { tecnicas: TecnicaMitre[]; tacticas: { tactica: string; conteo: number }[]; total: number };
  cobertura: CoverageData | null;
  auth: Autenticacion;
  ipsExternas: IpExterna[];
  fim: { total: number; added: number; modified: number; deleted: number; cambios: CambioFim[] };

  // Estado actual de la plataforma
  agentes: { total: number; activos: number; desconectados: number; items: AgenteTop[] };
  inventario: AgentItem[];
  vuln: VulnData | null;
  sca: ScaData | null;
  puertos: PortRow[];
  usuariosRiesgo: UserRow[];
  iocMatches: IocMatch[];
  supresiones: Suppression[];
  reglasPropias: { id: number; level: number; description: string; groups: string[] }[];

  // Operacion
  gestion: GestionIncidentes;
  anomalias: AnomaliaUeba[];
  bloqueos: BloqueoAplicado[];
  salud: SaludTelemetria;
}

// --------------------------------------------------------------------------
// Utilidades
// --------------------------------------------------------------------------

const IDX = () => `/${env.WAZUH_ALERTS_INDEX}`;

/** Rutas cuyo cambio siempre merece revision manual. */
const RUTAS_CRITICAS = [
  '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
  '/etc/crontab', '/etc/hosts', '/root/.ssh', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
  '\\System32\\', '\\SysWOW64\\',
];

function esRutaCritica(p: string): boolean {
  const l = p.toLowerCase();
  return RUTAS_CRITICAS.some((r) => l.includes(r.toLowerCase()));
}

function pctCambio(actual: number, previo: number): number | null {
  if (previo === 0) return actual === 0 ? 0 : null;
  return Math.round(((actual - previo) / previo) * 100);
}

function promedio(xs: number[]): number | null {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
}

function minutosEntre(a: string, b: string): number {
  return (new Date(b).getTime() - new Date(a).getTime()) / 60_000;
}

function intervalo(p: Periodo): string {
  return p.granularidad === 'hora' ? '1h'
    : p.granularidad === 'dia' ? '1d'
    : p.granularidad === 'semana' ? '1w' : '1M';
}

/** Filtro base del periodo. */
function rango(p: Periodo) {
  return { range: { timestamp: { gte: p.gte, lt: p.lt } } };
}

/** Reglas marcadas como falso positivo conocido (se excluyen de severidades). */
// Exclusión de ruido benigno CONSISTENTE con los dashboards afinados (mismo criterio
// que exec.data): el informe técnico debe contar la misma verdad que los paneles.
function reglasExcluidas(): unknown[] {
  const envIds = env.REPORT_EXCLUDE_RULES.split(',').map((s) => s.trim()).filter(Boolean);
  const noiseRuleIds = ['81633', '80792', '550', '752', '91578', ...envIds];
  return [{
    bool: {
      must_not: [
        { terms: { 'rule.id': noiseRuleIds } },
        { terms: { 'rule.groups': ['sca', 'vulnerability-detector'] } },
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

type Buckets<T = Record<string, unknown>> = { buckets: ({ key: string; doc_count: number } & T)[] };

async function search<T>(body: unknown): Promise<T | null> {
  try {
    const { data } = await getIndexerClient().post<T>(`${IDX()}/_search`, body);
    return data;
  } catch {
    return null;
  }
}

async function contar(p: Periodo, extra: unknown[] = []): Promise<number> {
  try {
    const { data } = await getIndexerClient().post<{ count: number }>(`${IDX()}/_count`, {
      query: { bool: { filter: [rango(p), ...extra] } },
    });
    return data.count;
  } catch {
    return 0;
  }
}

// --------------------------------------------------------------------------
// Bloques de recoleccion
// --------------------------------------------------------------------------

/** Distribucion por nivel de regla de Wazuh. */
async function volumenPorNivel(p: Periodo): Promise<TechMetrics['porNivel']> {
  const bandas: [string, string, number, number][] = [
    ['Informativo', 'niveles 0–3', 0, 3],
    ['Baja', 'niveles 4–7', 4, 7],
    ['Alta', 'niveles 8–11', 8, 11],
    ['Crítica', 'niveles 12–15', 12, 15],
  ];
  const out: TechMetrics['porNivel'] = [];
  for (const [banda, rangoTxt, min, max] of bandas) {
    out.push({
      banda,
      rango: rangoTxt,
      conteo: await contar(p, [{ range: { 'rule.level': { gte: min, lte: max } } }]),
    });
  }
  return out;
}

/** Serie temporal + deteccion de picos (buckets por encima de 2x la mediana). */
async function serieYPicos(p: Periodo): Promise<{ serie: SeriePunto[]; picos: TechMetrics['picos'] }> {
  const data = await search<{
    aggregations: { t: Buckets<{ crit: { doc_count: number } }> };
  }>({
    size: 0,
    query: { bool: { filter: [rango(p)] } },
    aggs: {
      t: {
        date_histogram: {
          field: 'timestamp',
          calendar_interval: intervalo(p),
          time_zone: 'America/Bogota',
          min_doc_count: 0,
          // `lt` es exclusivo: si se usa tal cual, el histograma crea un bucket
          // final vacio que se leeria como una interrupcion de ingesta.
          extended_bounds: { min: p.gte, max: new Date(new Date(p.lt).getTime() - 1).toISOString() },
        },
        aggs: { crit: { filter: { range: { 'rule.level': { gte: 12 } } } } },
      },
    },
  });
  const buckets = data?.aggregations?.t?.buckets ?? [];
  const serie: SeriePunto[] = buckets.map((b) => ({
    ts: (b as unknown as { key_as_string: string }).key_as_string,
    total: b.doc_count,
    criticos: b.crit?.doc_count ?? 0,
  }));

  // Pico = bucket cuyo volumen supera 2x la mediana de los buckets con datos.
  const conDatos = serie.filter((s) => s.total > 0).map((s) => s.total).sort((a, b) => a - b);
  const mediana = conDatos.length ? conDatos[Math.floor(conDatos.length / 2)] : 0;
  const picos = mediana > 0
    ? serie
        .filter((s) => s.total > mediana * 2)
        .map((s) => ({ ts: s.ts, total: s.total, vecesMedia: Math.round((s.total / mediana) * 10) / 10 }))
        .sort((a, b) => b.total - a.total)
        .slice(0, 5)
    : [];
  return { serie, picos };
}

/** Reglas que mas dispararon, con contexto para decidir tuning. */
async function topReglas(p: Periodo, total: number): Promise<ReglaTop[]> {
  const data = await search<{
    aggregations: {
      r: Buckets<{
        d: { hits: { hits: { _source: { rule?: { description?: string; level?: number; groups?: string[]; mitre?: { id?: string[] } } } }[] } };
        ag: { value: number };
      }>;
    };
  }>({
    size: 0,
    query: { bool: { filter: [rango(p)] } },
    aggs: {
      r: {
        terms: { field: 'rule.id', size: 15 },
        aggs: {
          d: { top_hits: { size: 1, _source: ['rule.description', 'rule.level', 'rule.groups', 'rule.mitre.id'] } },
          ag: { cardinality: { field: 'agent.name' } },
        },
      },
    },
  });
  return (data?.aggregations?.r?.buckets ?? []).map((b) => {
    const r = b.d?.hits?.hits?.[0]?._source?.rule ?? {};
    return {
      ruleId: b.key,
      descripcion: r.description ?? '(sin descripción)',
      nivel: r.level ?? 0,
      grupos: r.groups ?? [],
      conteo: b.doc_count,
      pctVolumen: total ? Math.round((b.doc_count / total) * 1000) / 10 : 0,
      agentes: b.ag?.value ?? 0,
      mitre: r.mitre?.id ?? [],
    };
  });
}

/** Agentes con mas actividad, desglosada por severidad. */
async function topAgentes(p: Periodo): Promise<AgenteTop[]> {
  const data = await search<{
    aggregations: {
      a: Buckets<{ crit: { doc_count: number }; alto: { doc_count: number }; reglas: { value: number } }>;
    };
  }>({
    size: 0,
    query: { bool: { filter: [rango(p)] } },
    aggs: {
      a: {
        terms: { field: 'agent.name', size: 12 },
        aggs: {
          crit: { filter: { range: { 'rule.level': { gte: 12 } } } },
          alto: { filter: { range: { 'rule.level': { gte: 8, lte: 11 } } } },
          reglas: { cardinality: { field: 'rule.id' } },
        },
      },
    },
  });
  return (data?.aggregations?.a?.buckets ?? []).map((b) => ({
    agente: b.key,
    total: b.doc_count,
    criticos: b.crit?.doc_count ?? 0,
    altos: b.alto?.doc_count ?? 0,
    reglasDistintas: b.reglas?.value ?? 0,
  }));
}

/** Nombres de todos los agentes que generaron al menos un evento. */
async function agentesConEventos(p: Periodo): Promise<Set<string>> {
  const data = await search<{ aggregations: { a: Buckets } }>({
    size: 0,
    query: { bool: { filter: [rango(p)] } },
    aggs: { a: { terms: { field: 'agent.name', size: 500 } } },
  });
  return new Set((data?.aggregations?.a?.buckets ?? []).map((b) => b.key));
}

/** Tecnicas y tacticas ATT&CK observadas en el periodo. */
async function mitreDelPeriodo(p: Periodo): Promise<TechMetrics['mitre']> {
  const data = await search<{
    hits: { total: { value: number } };
    aggregations: {
      tec: Buckets<{ nombre: Buckets; tac: Buckets; nivel: { value: number | null } }>;
      tac: Buckets;
    };
  }>({
    size: 0,
    track_total_hits: true,
    query: { bool: { filter: [rango(p), { exists: { field: 'rule.mitre.id' } }] } },
    aggs: {
      tec: {
        terms: { field: 'rule.mitre.id', size: 12 },
        aggs: {
          nombre: { terms: { field: 'rule.mitre.technique', size: 1 } },
          tac: { terms: { field: 'rule.mitre.tactic', size: 4 } },
          nivel: { max: { field: 'rule.level' } },
        },
      },
      tac: { terms: { field: 'rule.mitre.tactic', size: 14 } },
    },
  });
  const tecnicas: TecnicaMitre[] = (data?.aggregations?.tec?.buckets ?? []).map((b) => ({
    id: b.key,
    nombre: b.nombre?.buckets?.[0]?.key ?? '',
    tacticas: (b.tac?.buckets ?? []).map((t) => t.key),
    conteo: b.doc_count,
    nivelMax: b.nivel?.value ?? 0,
  }));
  return {
    tecnicas,
    tacticas: (data?.aggregations?.tac?.buckets ?? []).map((b) => ({ tactica: b.key, conteo: b.doc_count })),
    total: data?.hits?.total?.value ?? 0,
  };
}

/** Panorama de autenticacion: fallos, exitos, usuarios objetivo y origenes. */
async function autenticacion(p: Periodo): Promise<Autenticacion> {
  const fFallo = { terms: { 'rule.groups': ['authentication_failed', 'authentication_failures', 'win_authentication_failed'] } };
  const fExito = { terms: { 'rule.groups': ['authentication_success'] } };

  const [fallos, exitos] = await Promise.all([
    contar(p, [fFallo]),
    contar(p, [fExito]),
  ]);

  const dataF = await search<{
    aggregations: { u: Buckets; ip: Buckets };
  }>({
    size: 0,
    query: { bool: { filter: [rango(p), fFallo] } },
    aggs: {
      u: { terms: { field: 'data.srcuser', size: 10 } },
      ip: { terms: { field: 'data.srcip', size: 10 } },
    },
  });
  const dataE = await search<{ aggregations: { u: Buckets } }>({
    size: 0,
    query: { bool: { filter: [rango(p), fExito] } },
    aggs: { u: { terms: { field: 'data.dstuser', size: 8 } } },
  });

  return {
    fallos,
    exitos,
    ratioFallo: fallos + exitos > 0 ? Math.round((fallos / (fallos + exitos)) * 100) : null,
    usuariosAtacados: (dataF?.aggregations?.u?.buckets ?? []).map((b) => ({ usuario: b.key, fallos: b.doc_count })),
    ipsOrigen: (dataF?.aggregations?.ip?.buckets ?? []).map((b) => ({
      ip: b.key,
      publica: isPublicIP(b.key),
      pais: isPublicIP(b.key) ? (geolocate(b.key)?.country ?? null) : null,
      fallos: b.doc_count,
    })),
    usuariosConExito: (dataE?.aggregations?.u?.buckets ?? []).map((b) => ({ usuario: b.key, exitos: b.doc_count })),
  };
}

/** IPs publicas con actividad, ordenadas por relevancia (nivel + diversidad). */
async function ipsExternas(p: Periodo): Promise<IpExterna[]> {
  const agg = (campo: string) => ({
    terms: { field: campo, size: 60 },
    aggs: {
      nivel: { max: { field: 'rule.level' } },
      reglas: { cardinality: { field: 'rule.id' } },
      ag: { terms: { field: 'agent.name', size: 5 } },
      primera: { min: { field: 'timestamp' } },
      ultima: { max: { field: 'timestamp' } },
      muestra: { top_hits: { size: 1, _source: ['rule.description'] } },
    },
  });
  const data = await search<{
    aggregations: {
      src: Buckets<Record<string, never>>;
      rem: Buckets<Record<string, never>>;
    };
  }>({
    size: 0,
    query: { bool: { filter: [rango(p), ...reglasExcluidas()] } },
    aggs: { src: agg('data.srcip'), rem: agg('data.remip') },
  });

  type B = {
    key: string; doc_count: number;
    nivel?: { value: number | null }; reglas?: { value: number };
    ag?: Buckets; primera?: { value_as_string?: string }; ultima?: { value_as_string?: string };
    muestra?: { hits: { hits: { _source: { rule?: { description?: string } } }[] } };
  };
  const todos = [
    ...((data?.aggregations?.src?.buckets ?? []) as unknown as B[]),
    ...((data?.aggregations?.rem?.buckets ?? []) as unknown as B[]),
  ];

  // Une los buckets de ambos campos por IP
  const porIp = new Map<string, IpExterna>();
  for (const b of todos) {
    if (!isPublicIP(b.key)) continue;
    const prev = porIp.get(b.key);
    const item: IpExterna = {
      ip: b.key,
      pais: geolocate(b.key)?.country ?? null,
      conteo: b.doc_count + (prev?.conteo ?? 0),
      nivelMax: Math.max(b.nivel?.value ?? 0, prev?.nivelMax ?? 0),
      reglasDistintas: Math.max(b.reglas?.value ?? 0, prev?.reglasDistintas ?? 0),
      agentes: [...new Set([...(prev?.agentes ?? []), ...((b.ag?.buckets ?? []).map((x) => x.key))])],
      primeraVez: prev?.primeraVez ?? b.primera?.value_as_string ?? '',
      ultimaVez: b.ultima?.value_as_string ?? prev?.ultimaVez ?? '',
      reglaEjemplo: prev?.reglaEjemplo || b.muestra?.hits?.hits?.[0]?._source?.rule?.description || '',
    };
    porIp.set(b.key, item);
  }
  return [...porIp.values()]
    .sort((a, b) => (b.nivelMax * 1000 + b.reglasDistintas * 50 + Math.log10(b.conteo + 1) * 10)
      - (a.nivelMax * 1000 + a.reglasDistintas * 50 + Math.log10(a.conteo + 1) * 10))
    .slice(0, 12);
}

/** Cambios de integridad de archivos dentro del periodo. */
async function fimDelPeriodo(p: Periodo): Promise<TechMetrics['fim']> {
  const filtro = { exists: { field: 'syscheck.path' } };
  const data = await search<{
    hits: {
      total: { value: number };
      hits: {
        _source: {
          syscheck?: { path?: string; event?: string; uname_after?: string };
          agent?: { name?: string };
          rule?: { level?: number };
          timestamp?: string;
        };
      }[];
    };
    aggregations: { ev: Buckets };
  }>({
    size: 40,
    track_total_hits: true,
    sort: [{ 'rule.level': 'desc' }, { timestamp: 'desc' }],
    _source: ['syscheck.path', 'syscheck.event', 'syscheck.uname_after', 'agent.name', 'rule.level', 'timestamp'],
    query: { bool: { filter: [rango(p), filtro] } },
    aggs: { ev: { terms: { field: 'syscheck.event', size: 5 } } },
  });

  const ev = new Map((data?.aggregations?.ev?.buckets ?? []).map((b) => [b.key, b.doc_count]));
  const cambios: CambioFim[] = (data?.hits?.hits ?? []).map((h) => {
    const ruta = h._source.syscheck?.path ?? '';
    return {
      ruta,
      evento: h._source.syscheck?.event ?? '',
      agente: h._source.agent?.name ?? '',
      usuario: h._source.syscheck?.uname_after ?? '',
      nivel: h._source.rule?.level ?? 0,
      ts: h._source.timestamp ?? '',
      critico: esRutaCritica(ruta),
    };
  });
  // Primero lo sensible, luego por nivel
  cambios.sort((a, b) => Number(b.critico) - Number(a.critico) || b.nivel - a.nivel);

  return {
    total: data?.hits?.total?.value ?? 0,
    added: ev.get('added') ?? 0,
    modified: ev.get('modified') ?? 0,
    deleted: ev.get('deleted') ?? 0,
    cambios: cambios.slice(0, 15),
  };
}

/** Gestion de incidentes del periodo, con detalle de incumplimientos. */
async function gestionDelPeriodo(p: Periodo): Promise<GestionIncidentes> {
  const vacio: GestionIncidentes = {
    total: 0,
    porSeveridad: { baja: 0, media: 0, alta: 0, critica: 0 },
    porEstado: {},
    resueltos: 0, abiertos: 0,
    mttaMinutos: null, mttrMinutos: null, cumplimientoSlaPct: null,
    incumplidos: [], antiguos: [],
  };
  const rows = await query<{
    id: string; title: string; severity: SevIncidente; status: string;
    created_at: string; closed_at: string | null; first_action: string | null;
  }>(
    `SELECT i.id, i.title, i.severity, i.status, i.created_at, i.closed_at,
            (SELECT min(n.created_at) FROM incident_notes n
               WHERE n.incident_id = i.id AND n.note NOT ILIKE 'Incidente creado%') AS first_action
       FROM incidents i
      WHERE i.created_at >= $1 AND i.created_at < $2
      ORDER BY i.created_at`,
    [p.gte, p.lt]
  ).catch(() => []);
  if (rows.length === 0) return vacio;

  const out: GestionIncidentes = { ...vacio, porSeveridad: { baja: 0, media: 0, alta: 0, critica: 0 }, porEstado: {}, incumplidos: [], antiguos: [] };
  const mtta: number[] = [];
  const mttr: number[] = [];
  let evaluados = 0;
  let cumplidos = 0;
  const ahora = Date.now();

  for (const r of rows) {
    out.total++;
    if (r.severity in out.porSeveridad) out.porSeveridad[r.severity]++;
    out.porEstado[r.status] = (out.porEstado[r.status] ?? 0) + 1;
    const cerrado = r.status === 'resuelto' || r.status === 'cerrado';
    if (cerrado) out.resueltos++;
    else {
      out.abiertos++;
      const dias = Math.round((ahora - new Date(r.created_at).getTime()) / 86_400_000);
      if (dias > 7) out.antiguos.push({ id: r.id, titulo: r.title, severidad: r.severity, dias });
    }
    const objetivo = (SLA_TARGETS[r.severity] ?? SLA_TARGETS.media).responseMin;
    if (r.first_action) {
      const d = minutosEntre(r.created_at, r.first_action);
      if (d >= 0) {
        mtta.push(d);
        evaluados++;
        if (d <= objetivo) cumplidos++;
        else out.incumplidos.push({ id: r.id, titulo: r.title, severidad: r.severity, minutos: Math.round(d), objetivo });
      }
    }
    if (cerrado && r.closed_at) {
      const d = minutosEntre(r.created_at, r.closed_at);
      if (d > 0) mttr.push(d);
    }
  }

  out.mttaMinutos = promedio(mtta);
  out.mttrMinutos = promedio(mttr);
  out.cumplimientoSlaPct = evaluados ? Math.round((cumplidos / evaluados) * 100) : null;
  out.incumplidos.sort((a, b) => b.minutos - a.minutos);
  out.antiguos.sort((a, b) => b.dias - a.dias);
  out.incumplidos = out.incumplidos.slice(0, 8);
  out.antiguos = out.antiguos.slice(0, 8);
  return out;
}

/** Salud de la telemetria: huecos de ingesta y agentes mudos. */
async function saludTelemetria(
  p: Periodo,
  serie: SeriePunto[],
  agentesConEventos: Set<string>,
  inventario: AgentItem[]
): Promise<SaludTelemetria> {
  const vacios = serie.filter((s) => s.total === 0);
  // Mayor racha continua sin datos
  let mayor: SaludTelemetria['mayorHueco'] = null;
  let racha = 0;
  let inicio = '';
  const horasPorBucket = p.granularidad === 'hora' ? 1 : p.granularidad === 'dia' ? 24 : 168;
  for (const s of serie) {
    if (s.total === 0) {
      if (racha === 0) inicio = s.ts;
      racha++;
    } else {
      if (racha > 0 && (!mayor || racha * horasPorBucket > mayor.horas)) {
        mayor = { desde: inicio, horas: racha * horasPorBucket };
      }
      racha = 0;
    }
  }
  if (racha > 0 && (!mayor || racha * horasPorBucket > mayor.horas)) {
    mayor = { desde: inicio, horas: racha * horasPorBucket };
  }

  const activos = inventario.filter((a) => a.status === 'active');
  const versiones = new Map<string, number>();
  for (const a of inventario) {
    const v = (a.version || 'desconocida').replace(/^Wazuh\s*/i, '');
    versiones.set(v, (versiones.get(v) ?? 0) + 1);
  }

  return {
    bucketsVacios: vacios.length,
    bucketsTotales: serie.length,
    mayorHueco: mayor,
    agentesSinEventos: activos.filter((a) => !agentesConEventos.has(a.name)).map((a) => a.name),
    agentesDesconectados: inventario
      .filter((a) => a.status !== 'active')
      .map((a) => ({ agente: a.name, ultimoContacto: a.lastKeepAlive })),
    versionesAgente: [...versiones.entries()]
      .map(([version, agentes]) => ({ version, agentes }))
      .sort((a, b) => b.agentes - a.agentes),
  };
}

// --------------------------------------------------------------------------
// Recoleccion principal
// --------------------------------------------------------------------------

export async function collectTechMetrics(p: Periodo, titulo: string): Promise<TechMetrics> {
  const prev = periodoAnterior(p);

  const [total, { serie, picos }, porNivel] = await Promise.all([
    contar(p),
    serieYPicos(p),
    volumenPorNivel(p),
  ]);

  const notNoise = reglasExcluidas();
  const [criticos, altos, medios, bajos, totalPrev, critPrev, reglasCard] = await Promise.all([
    contar(p, [{ range: { 'rule.level': { gte: 12 } } }, ...notNoise]),
    contar(p, [{ range: { 'rule.level': { gte: 8, lte: 11 } } }, ...notNoise]),
    contar(p, [{ range: { 'rule.level': { gte: 5, lte: 7 } } }, ...notNoise]),
    contar(p, [{ range: { 'rule.level': { lte: 4 } } }]),
    contar(prev),
    contar(prev, [{ range: { 'rule.level': { gte: 12 } } }, ...notNoise]),
    search<{ aggregations: { c: { value: number } } }>({
      size: 0, query: { bool: { filter: [rango(p)] } }, aggs: { c: { cardinality: { field: 'rule.id' } } },
    }),
  ]);

  const [reglas, agentesTop, conEventos, mitre, auth, ips, fim, gestion] = await Promise.all([
    topReglas(p, total),
    topAgentes(p),
    agentesConEventos(p),
    mitreDelPeriodo(p),
    autenticacion(p),
    ipsExternas(p),
    fimDelPeriodo(p),
    gestionDelPeriodo(p),
  ]);

  // Estado actual de la plataforma (tolerante a modulos sin datos)
  const [resumenAgentes, inventario, vuln, sca, cobertura, puertos, usuarios, iocMatches, supresiones, reglasPropias] =
    await Promise.all([
      getAgentsSummary().catch(() => ({ total: 0, active: 0, disconnected: 0, neverConnected: 0, pending: 0 })),
      getAgents(100).then((xs) => xs.filter((a) => a.id !== '000')).catch(() => [] as AgentItem[]),
      getVulnerabilities().catch(() => null),
      getSca().catch(() => null),
      getCoverage(Math.min(Math.max(p.dias, 1), 90)).catch(() => null),
      getPorts().catch(() => [] as PortRow[]),
      getUsers().catch(() => ({ porAgente: [], riesgo: [] as UserRow[] })),
      getMatches().catch(() => [] as IocMatch[]),
      listSuppressions().catch(() => [] as Suppression[]),
      getCustomRules().catch(() => [] as { id: number; level: number; description: string; groups: string[] }[]),
    ]);

  // Operacion registrada en la base de datos
  const [anomalias, bloqueos] = await Promise.all([
    query<{ detector: string; entity: string; severity: string; score: number; title: string; status: string; last_seen: string }>(
      `SELECT detector, entity, severity, score, title, status, last_seen
         FROM ueba_anomalies WHERE last_seen >= $1 AND last_seen < $2
        ORDER BY score DESC LIMIT 15`,
      [p.gte, p.lt]
    ).catch(() => []),
    query<{ ip: string; motivo: string | null; created_at: string }>(
      `SELECT DISTINCT ON (ip) ip, motivo, created_at FROM block_actions
        WHERE accion='block' AND resultado='success' AND created_at >= $1 AND created_at < $2
        ORDER BY ip, created_at DESC`,
      [p.gte, p.lt]
    ).catch(() => []),
  ]);

  const salud = await saludTelemetria(p, serie, conEventos, inventario);

  return {
    periodo: p,
    generadoEn: new Date().toISOString(),
    titulo,

    total,
    porNivel,
    criticos, altos, medios, bajos,
    anterior: { total: totalPrev, criticos: critPrev },
    variacion: { total: pctCambio(total, totalPrev), criticos: pctCambio(criticos, critPrev) },

    serie,
    picos,

    topReglas: reglas,
    topAgentes: agentesTop,
    reglasDistintas: reglasCard?.aggregations?.c?.value ?? 0,

    mitre,
    cobertura,
    auth,
    ipsExternas: ips,
    fim,

    agentes: {
      total: resumenAgentes.total,
      activos: resumenAgentes.active,
      desconectados: resumenAgentes.disconnected ?? 0,
      items: agentesTop,
    },
    inventario,
    vuln,
    sca,
    puertos,
    usuariosRiesgo: usuarios.riesgo ?? [],
    iocMatches,
    supresiones,
    reglasPropias,

    gestion,
    anomalias: anomalias.map((a) => ({
      detector: a.detector, entidad: a.entity, severidad: a.severity,
      score: a.score, titulo: a.title, estado: a.status, ts: a.last_seen,
    })),
    bloqueos: bloqueos.map((b) => ({
      ip: b.ip, motivo: b.motivo, ts: b.created_at,
      pais: isPublicIP(b.ip) ? (geolocate(b.ip)?.country ?? null) : null,
    })),
    salud,
  };
}

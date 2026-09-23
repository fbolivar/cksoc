/**
 * Datos del PARTE DE ESTADO (shift report) — el "parte de turno" que se envía
 * al cliente dos veces al día. Resume el estado REAL de las estaciones/servidores
 * y la actividad del SOC en el turno. Reutiliza la clasificación ya afinada de
 * agentes y el cliente del Indexer; aplica la misma exclusión de ruido benigno
 * que los dashboards para que las cifras muestren señal, no ruido.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { getClientAgents } from '../wazuh/agents.service';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { query } from '../../config/db';
import { getO365Overview } from '../office365/o365.service';

export type Turno = 'am' | 'pm';

export interface AtencionItem {
  host: string;
  motivo: string;
  ghost: boolean;
}

export interface ShiftReportData {
  turno: Turno;
  turnoLabel: string;
  fecha: string; // fecha larga es-CO
  hora: string; // HH:mm
  ventanaLabel: string;
  totalEndpoints: number;
  estaciones: number;
  servidores: number;
  wkEnLinea: number;
  wkApagadas: number;
  wkAtencion: number;
  atencion: AtencionItem[];
  eventos12h: number;
  incidentesCriticos: number;
  altaSeveridad30d: number;
  equiposActivos: { name: string; kind: string }[];
  equiposInactivos: { name: string; kind: string; motivo: string }[];
  topIncidentes: { titulo: string; severidad: string; estado: string; creado: string }[];
  topAmenazas: { label: string; count: number }[];
  estacionesActivas: { host: string; eventos: number }[];
  equiposSesiones: { host: string; kind: string; conecto: string | null; desconecto: string | null; enLinea: boolean }[];
  correo: { configured: boolean; total: number; signIns: number; signInsFailed: number; usuarios: number; riesgos: { label: string; count: number; severity: string }[] };
  generadoEn: string; // ISO
}

// Exclusión de ruido benigno estándar (consistente con Reportes/dashboards).
function noiseFilter(): unknown {
  const envIds = (env.REPORT_EXCLUDE_RULES || '').split(',').map((s) => s.trim()).filter(Boolean);
  const noiseRuleIds = ['81633', '80792', '550', '752', '91578', ...envIds];
  return {
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
  };
}

async function count(body: unknown): Promise<number> {
  try {
    const { data } = await getIndexerClient().post<{ count: number }>(
      `${env.WAZUH_ALERTS_INDEX}/_count`,
      body
    );
    return data.count ?? 0;
  } catch (err) {
    logger.warn({ err }, 'shift-report: fallo al consultar el Indexer');
    return 0;
  }
}

async function aggTerms(body: unknown): Promise<{ key: string; count: number }[]> {
  try {
    const { data } = await getIndexerClient().post<{ aggregations?: { t: { buckets: { key: string; doc_count: number }[] } } }>(
      `${env.WAZUH_ALERTS_INDEX}/_search`, body);
    return (data.aggregations?.t?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count }));
  } catch (err) { logger.warn({ err }, 'shift-report: fallo agregacion'); return []; }
}

function turnoActual(): Turno {
  const h = Number(
    new Intl.DateTimeFormat('en-US', { hour: '2-digit', hour12: false, timeZone: env.DIGEST_TZ }).format(new Date())
  );
  return h < 12 ? 'am' : 'pm';
}

/** Recolecta todos los datos del parte para el turno indicado. */
export async function collectShiftData(turno: Turno = turnoActual()): Promise<ShiftReportData> {
  const agents = await getClientAgents(500);
  const est = agents.filter((a) => a.kind === 'estacion');
  const srv = agents.filter((a) => a.kind === 'servidor');

  const wkEnLinea = est.filter((a) => a.health === 'ok').length;
  const wkApagadas = est.filter((a) => a.health === 'apagado').length;
  const atencion = est
    .filter((a) => a.needsAttention)
    .map((a) => ({ host: a.name, motivo: a.motivo, ghost: a.health === 'fantasma' }));

  const w12 = { range: { '@timestamp': { gte: 'now-12h' } } };
  const w30 = { range: { '@timestamp': { gte: 'now-30d' } } };
  const critico = { range: { 'rule.level': { gte: 12 } } };

  const [eventos12h, incidentesCriticos, altaSeveridad30d] = await Promise.all([
    count({ query: w12 }), // throughput total (no se de-ruidea: es volumen procesado)
    count({ query: { bool: { filter: [w12, critico, noiseFilter()] } } }),
    count({ query: { bool: { filter: [w30, critico, noiseFilter()] } } }),
  ]);

  // Nombres de equipos activos (reportando) e inactivos (apagados/desconectados/fantasma).
  const equiposActivos = agents
    .filter((a) => a.health === 'ok')
    .map((a) => ({ name: a.name, kind: a.kind }));
  const equiposInactivos = agents
    .filter((a) => a.health !== 'ok')
    .map((a) => ({ name: a.name, kind: a.kind, motivo: a.motivo }));

  // Estado por EQUIPO (estacion): a que hora se conecto y desconecto hoy (hora Bogota).
  // Fuente: eventos de ciclo de vida del agente Wazuh (503 arranque; 504/506 parada).
  const equiposSesiones = await (async (): Promise<ShiftReportData['equiposSesiones']> => {
    const names = est.map((a) => a.name);
    if (!names.length) return [];
    const fmt = (v: string | null | undefined): string | null =>
      v ? new Date(v).toLocaleTimeString('es-CO', { timeZone: 'America/Bogota', hour: '2-digit', minute: '2-digit', hour12: false }) : null;
    try {
      const { data } = await getIndexerClient().post<{ aggregations?: { ag: { buckets: Array<{
        key: string; firstAny: { value_as_string?: string }; lastAny: { value_as_string?: string };
        conn: { t: { value_as_string?: string } }; disc: { t: { value_as_string?: string } };
      }> } } }>(`${env.WAZUH_ALERTS_INDEX}/_search`, {
        size: 0,
        query: { bool: { filter: [
          { range: { '@timestamp': { gte: 'now/d', time_zone: 'America/Bogota' } } },
          { terms: { 'agent.name': names } },
        ] } },
        aggs: { ag: { terms: { field: 'agent.name', size: names.length }, aggs: {
          firstAny: { min: { field: '@timestamp' } },
          lastAny: { max: { field: '@timestamp' } },
          conn: { filter: { term: { 'rule.id': '503' } }, aggs: { t: { min: { field: '@timestamp' } } } },
          disc: { filter: { terms: { 'rule.id': ['504', '506'] } }, aggs: { t: { max: { field: '@timestamp' } } } },
        } } },
      });
      const byName = new Map((data.aggregations?.ag?.buckets ?? []).map((b) => [b.key, b]));
      return est.map((a) => {
        const b = byName.get(a.name);
        const enLinea = a.health === 'ok';
        const conecto = fmt(b?.conn.t.value_as_string ?? b?.firstAny.value_as_string);
        const desconecto = enLinea ? null : fmt(b?.disc.t.value_as_string ?? b?.lastAny.value_as_string);
        return { host: a.name, kind: a.kind, conecto, desconecto, enLinea };
      }).sort((x, y) => (x.conecto ?? '99').localeCompare(y.conecto ?? '99'));
    } catch {
      return est.map((a) => ({ host: a.name, kind: a.kind, conecto: null, desconecto: null, enLinea: a.health === 'ok' }));
    }
  })();

  // Top 5 incidentes del ultimo mes (por severidad y recencia).
  const topIncidentes = await query<{ titulo: string; severidad: string; estado: string; creado: string }>(
    `SELECT titulo, severidad, estado, creado FROM (
        SELECT title AS titulo, severity AS severidad, status AS estado,
               to_char(created_at, 'DD/MM HH24:MI') AS creado, created_at,
               CASE severity WHEN 'critica' THEN 4 WHEN 'alta' THEN 3 WHEN 'media' THEN 2 ELSE 1 END AS sev_ord,
               ROW_NUMBER() OVER (PARTITION BY COALESCE(source->>'ip', id::text) ORDER BY created_at DESC) AS rn
          FROM incidents
         WHERE created_at >= now() - interval '30 days'
      ) x WHERE rn = 1
      ORDER BY sev_ord DESC, created_at DESC
      LIMIT 5`
  ).catch(() => [] as { titulo: string; severidad: string; estado: string; creado: string }[]);

  // Top 5 amenazas detectadas en el turno (tipos de alerta de mayor severidad, sin ruido).
  const amenazasRaw = await aggTerms({
    size: 0,
    query: { bool: { filter: [w12, { range: { 'rule.level': { gte: 7 } } }, noiseFilter()] } },
    aggs: { t: { terms: { field: 'rule.description', size: 5 } } },
  });
  const topAmenazas = amenazasRaw.map((x) => ({ label: x.key, count: x.count }));

  // Estaciones de trabajo mas activas (mas eventos en 12 h).
  const estNames = new Set(est.map((a) => a.name));
  const actRaw = await aggTerms({
    size: 0,
    query: { bool: { filter: [w12, { exists: { field: 'agent.name' } }] } },
    aggs: { t: { terms: { field: 'agent.name', size: 25 } } },
  });
  const estacionesActivas = actRaw
    .filter((x) => estNames.has(x.key))
    .slice(0, 5)
    .map((x) => ({ host: x.key, eventos: x.count }));

  // Actividad de Microsoft 365 (correo y colaboracion) del turno.
  const correo = await (async () => {
    try {
      const o = await getO365Overview('12h');
      return {
        configured: o.total > 0,
        total: o.total,
        signIns: o.signIns,
        signInsFailed: o.signInsFailed,
        usuarios: o.users,
        riesgos: o.risks.items.filter((i) => i.active).map((i) => ({ label: i.label, count: i.count, severity: i.severity })),
      };
    } catch {
      return { configured: false, total: 0, signIns: 0, signInsFailed: 0, usuarios: 0, riesgos: [] as { label: string; count: number; severity: string }[] };
    }
  })();

  const now = new Date();
  const fecha = new Intl.DateTimeFormat('es-CO', {
    weekday: 'long', day: '2-digit', month: 'long', year: 'numeric', timeZone: env.DIGEST_TZ,
  }).format(now);
  const hora = new Intl.DateTimeFormat('es-CO', {
    hour: '2-digit', minute: '2-digit', hour12: false, timeZone: env.DIGEST_TZ,
  }).format(now);

  return {
    turno,
    turnoLabel: turno === 'am' ? 'Turno Mañana' : 'Turno Tarde',
    fecha: fecha.charAt(0).toUpperCase() + fecha.slice(1),
    hora,
    ventanaLabel: 'últimas 12 h',
    totalEndpoints: agents.length,
    estaciones: est.length,
    servidores: srv.length,
    wkEnLinea,
    wkApagadas,
    wkAtencion: atencion.length,
    atencion,
    eventos12h,
    incidentesCriticos,
    altaSeveridad30d,
    equiposActivos,
    equiposInactivos,
    topIncidentes,
    topAmenazas,
    estacionesActivas,
    equiposSesiones,
    correo,
    generadoEn: now.toISOString(),
  };
}

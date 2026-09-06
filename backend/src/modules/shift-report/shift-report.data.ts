/**
 * Datos del PARTE DE ESTADO (shift report) — el "parte de turno" que se envía
 * al cliente dos veces al día. Resume el estado REAL de las estaciones/servidores
 * y la actividad del SOC en el turno. Reutiliza la clasificación ya afinada de
 * agentes y el cliente del Indexer; aplica la misma exclusión de ruido benigno
 * que los dashboards para que las cifras muestren señal, no ruido.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { getAgents } from '../wazuh/agents.service';
import { env } from '../../config/env';
import { logger } from '../../config/logger';

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

function turnoActual(): Turno {
  const h = Number(
    new Intl.DateTimeFormat('en-US', { hour: '2-digit', hour12: false, timeZone: env.DIGEST_TZ }).format(new Date())
  );
  return h < 12 ? 'am' : 'pm';
}

/** Recolecta todos los datos del parte para el turno indicado. */
export async function collectShiftData(turno: Turno = turnoActual()): Promise<ShiftReportData> {
  const agents = await getAgents(500);
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
    generadoEn: now.toISOString(),
  };
}

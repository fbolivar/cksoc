/**
 * Resumen Ejecutivo consolidado: una sola vista con la postura de todos los
 * dominios del SOC (amenazas, endpoints, cumplimiento, salud del SIEM, agentes).
 * Reutiliza los servicios de cada modulo, tolerante a fallos individuales.
 */
import { getOverallHealth } from '../health/siem-health.service';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { getSca } from '../sca/sca.service';
import { getCompliance } from '../compliance/compliance.service';
import { getFim } from '../fim/fim.service';
import { getSummary } from '../wazuh/wazuh.service';
import { getAgentsSummary } from '../wazuh/agents.service';
import { getAttackGeo } from '../attacks/attacks.service';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';

/** Conteo de eventos criticos (nivel>=12) en 24h, excluyendo falsos positivos
 *  conocidos (mismos que el reporte ejecutivo) para que ambos surfaces coincidan.
 *  Devuelve `null` si la consulta falla: "desconocido" no es lo mismo que 0, y
 *  jamas debemos pintar calma falsa por un timeout. Reintento suave + timeout
 *  amplio para sobrevivir a la concurrencia del Command Center. */
async function criticosReales24h(): Promise<number | null> {
  const exclude = env.REPORT_EXCLUDE_RULES.split(',').map((s) => s.trim()).filter(Boolean);
  const filter: unknown[] = [
    { range: { timestamp: { gte: 'now-24h' } } },
    { range: { 'rule.level': { gte: 12 } } },
  ];
  if (exclude.length) filter.push({ bool: { must_not: [{ terms: { 'rule.id': exclude } }] } });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const { data } = await getIndexerClient().post<{ count: number }>(
        `/${env.WAZUH_ALERTS_INDEX}/_count`, { query: { bool: { filter } } }, { timeout: 20_000 }
      );
      return data.count ?? 0;
    } catch {
      if (attempt === 0) await new Promise((r) => setTimeout(r, 350));
    }
  }
  return null;
}

export interface OverviewData {
  generadoEn: string;
  global: { semaforo: 'verde' | 'amarillo' | 'rojo'; motivo: string };
  amenazas: { alertas24h: number | null; criticas24h: number | null; altasCriticas24h: number | null; ataquesExternos: number };
  endpoints: { vulnCriticas: number; vulnAltas: number; vulnTotal: number; hardeningScore: number; fimCambios: number };
  cumplimiento: { marco: string; controles: number }[];
  siem: { semaforo: 'verde' | 'amarillo' | 'rojo'; ok: number; total: number };
  agentes: { activos: number | null; total: number | null };
  /** true si esta respuesta se sirvio de la ultima cache buena por un fallo transitorio. */
  degradado?: boolean;
}

let cache: { at: number; data: OverviewData } | null = null;
// Red de seguridad, no el reloj de frescura: quien marca el ritmo es el
// precalentado (overview.warmup), que fuerza una reconstruccion cada 25s. El
// TTL solo debe dejar margen suficiente para que una peticion de usuario nunca
// coincida con una cache recien expirada y acabe reconstruyendo ella misma.
const TTL = 60_000;

/**
 * Devuelve el resumen ejecutivo. Con `force` reconstruye aunque la cache siga
 * vigente: lo usa el precalentado para renovarla antes de que caduque, de modo
 * que ninguna peticion de usuario pague la reconstruccion.
 */
export async function getOverview(opts?: { force?: boolean }): Promise<OverviewData> {
  if (!opts?.force && cache && Date.now() - cache.at < TTL) return cache.data;

  const [health, vuln, sca, comp, fim, summary, agents, attacks, criticas24h] = await Promise.all([
    getOverallHealth().catch(() => null),
    getVulnerabilities().catch(() => null),
    getSca().catch(() => null),
    getCompliance(720).catch(() => null),
    getFim(168).catch(() => null),
    getSummary('24h').catch(() => null),
    getAgentsSummary().catch(() => null),
    getAttackGeo(168).catch(() => null),
    criticosReales24h(),
  ]);

  const altasCriticas24h = summary ? (summary.byBand.alta ?? 0) + (summary.byBand.critica ?? 0) : null;
  const ataquesExternos = attacks ? attacks.filter((o) => o.esExterno).length : 0;
  const vulnCriticas = vuln?.resumen.critical ?? 0;
  const hardeningScore = sca?.resumen.scorePromedio ?? 0;
  const siemSem = health?.semaforo ?? 'verde';
  const compsOk = health ? health.componentes.filter((c) => c.estado === 'ok').length : 0;
  const compsTotal = health ? health.componentes.length : 0;

  // Semaforo global: combina las señales de todos los dominios. Solo cuenta lo
  // que SÍ pudimos medir (criticas24h/salud); un valor desconocido no dispara ni
  // silencia el semaforo.
  const fallos: string[] = [];
  if (siemSem === 'rojo') fallos.push('la plataforma SIEM presenta fallos');
  if (criticas24h != null && criticas24h >= 5) fallos.push(`${criticas24h} eventos críticos en 24h`);

  const advertencias: string[] = [];
  if (vulnCriticas > 0) advertencias.push(`${vulnCriticas} vulnerabilidad(es) crítica(s)`);
  if (hardeningScore > 0 && hardeningScore < 60) advertencias.push(`hardening en ${hardeningScore}%`);
  if (ataquesExternos > 0) advertencias.push(`${ataquesExternos} origen(es) externo(s) marcados`);
  if (criticas24h != null && criticas24h > 0 && criticas24h < 5) advertencias.push('eventos críticos recientes');
  if (siemSem === 'amarillo') advertencias.push('advertencias en el SIEM');

  let semaforo: 'verde' | 'amarillo' | 'rojo' = 'verde';
  let motivo = 'Todos los dominios operan dentro de parámetros normales.';
  if (fallos.length) {
    semaforo = 'rojo';
    motivo = `Requiere atención: ${fallos.join('; ')}.`;
  } else if (advertencias.length) {
    semaforo = 'amarillo';
    motivo = `Bajo gestión: ${advertencias.join('; ')}.`;
  }

  const data: OverviewData = {
    generadoEn: new Date().toISOString(),
    global: { semaforo, motivo },
    amenazas: {
      alertas24h: summary ? summary.total : null,
      criticas24h,
      altasCriticas24h,
      ataquesExternos,
    },
    endpoints: {
      vulnCriticas,
      vulnAltas: vuln?.resumen.high ?? 0,
      vulnTotal: vuln?.resumen.total ?? 0,
      hardeningScore,
      fimCambios: fim?.resumen.total ?? 0,
    },
    cumplimiento: comp
      ? [
          { marco: 'NIST 800-53', controles: comp.frameworks.nist?.controles.length ?? 0 },
          { marco: 'GDPR', controles: comp.frameworks.gdpr?.controles.length ?? 0 },
          { marco: 'TSC', controles: comp.frameworks.tsc?.controles.length ?? 0 },
          { marco: 'PCI DSS', controles: comp.frameworks.pci?.controles.length ?? 0 },
        ]
      : [],
    siem: { semaforo: siemSem, ok: compsOk, total: compsTotal },
    agentes: { activos: agents?.active ?? null, total: agents?.total ?? null },
  };

  // Degradado = no pudimos medir las cifras cabecera (alertas o agentes o
  // criticas). En ese caso NO envenenamos la cache con ceros: servimos la ultima
  // foto buena (real aunque un poco vieja); si no hay, devolvemos "desconocido"
  // sin cachear, para reintentar en la siguiente llamada.
  const degradado = summary === null || agents === null || criticas24h === null;
  if (!degradado) {
    cache = { at: Date.now(), data };
    return data;
  }
  if (cache) return { ...cache.data, degradado: true };
  return { ...data, degradado: true };
}

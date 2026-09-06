/**
 * Tablero Ejecutivo de Riesgo: traduce las metricas tecnicas de la plataforma
 * a los 6 dominios de riesgo del negocio, con semaforo, la pregunta de negocio
 * que responde cada uno, y un indice de postura compuesto.
 *
 * Honestidad: los KPIs sin fuente de datos (factor humano, PAM, DR test formal)
 * se marcan con status 'pending' en vez de inventar cifras.
 */
import { query } from '../../config/db';
import { getSocMetrics } from '../metrics/metrics.service';
import { getVulnerabilities } from '../vulnerabilities/vuln.service';
import { getSca } from '../sca/sca.service';
import { getAgents } from '../wazuh/agents.service';
import { listBackups } from '../backups/backups.service';
import { getHumanFactor } from '../phishing/phishing.service';
import { logger } from '../../config/logger';

export type Status = 'good' | 'warn' | 'bad' | 'pending';

export interface Kpi {
  label: string;
  value: string;
  status: Status;
  source: 'real' | 'pending';
  note?: string;
}
export interface Domain {
  key: string;
  title: string;
  businessQuestion: string;
  status: Status;
  posture: number | null; // 0-100 (mayor = mejor), null si pendiente
  kpis: Kpi[];
}
export interface RiskBoard {
  generatedAt: string;
  index: { score: number; level: 'bajo' | 'medio' | 'alto' | 'critico'; label: string; measuredDomains: number };
  overallQuestion: string;
  domains: Domain[];
}

const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));
/** Semaforo para posturas donde MAYOR es mejor. */
const st = (posture: number, good = 80, warn = 60): Status =>
  posture >= good ? 'good' : posture >= warn ? 'warn' : 'bad';

function levelFromScore(s: number): { level: 'bajo' | 'medio' | 'alto' | 'critico'; label: string } {
  if (s >= 80) return { level: 'bajo', label: 'Riesgo bajo' };
  if (s >= 60) return { level: 'medio', label: 'Riesgo medio' };
  if (s >= 40) return { level: 'alto', label: 'Riesgo alto' };
  return { level: 'critico', label: 'Riesgo crítico' };
}

export async function getRiskBoard(): Promise<RiskBoard> {
  const domains: Domain[] = [];

  // ---------- 1. Detectar y responder ----------
  try {
    const m = await getSocMetrics(30);
    // Tasa alta de FP = detecciones ruidosas (a afinar), no es "bueno".
    const fpr = m.quality.falsePositiveRate;
    const fpStatus: Status = fpr === null ? 'pending' : fpr <= 20 ? 'good' : fpr <= 50 ? 'warn' : 'bad';
    const fpRateKpi = { label: 'Tasa de falsos positivos', value: fpr === null ? 's/d' : `${fpr}%`, status: fpStatus, source: (fpr === null ? 'pending' : 'real') as 'pending' | 'real', note: fpr !== null && fpr > 50 ? 'Detecciones ruidosas: conviene afinar reglas' : undefined };
    if (m.quality.realTotal === 0) {
      // Sin incidentes reales: no hay tiempos que medir. NO es "malo" (antes esto
      // daba SLA 0 → crítico); la postura la marca el backlog: nada pendiente = sano.
      const posture = m.aging.openOver24h === 0 ? 100 : clamp(100 - m.aging.openOver24h * 15);
      domains.push({
        key: 'deteccion', title: 'Detectar y responder',
        businessQuestion: '¿Reducimos el tiempo en que una amenaza activa está sin contener?',
        status: st(posture), posture,
        kpis: [
          { label: 'Incidentes reales (30d)', value: '0', status: 'good', source: 'real', note: `${m.quality.excludedFromMetrics} falso(s) positivo(s)/prueba depurados` },
          { label: 'Incidentes abiertos > 24h', value: String(m.aging.openOver24h), status: m.aging.openOver24h === 0 ? 'good' : m.aging.openOver24h <= 3 ? 'warn' : 'bad', source: 'real' },
          { label: 'Cumplimiento de SLA', value: 's/d', status: 'pending', source: 'pending', note: 'Sin incidentes reales que medir en el periodo' },
          fpRateKpi,
        ],
      });
    } else {
      const sla = m.sla.overallPct ?? 0;
      const posture = clamp(sla);
      domains.push({
        key: 'deteccion', title: 'Detectar y responder',
        businessQuestion: '¿Reducimos el tiempo en que una amenaza activa está sin contener?',
        status: st(posture), posture,
        kpis: [
          { label: 'Cumplimiento de SLA', value: m.sla.overallPct === null ? 's/d' : `${m.sla.overallPct}%`, status: st(sla), source: 'real', note: 'Sobre incidentes reales (excluye falsos positivos)' },
          { label: 'MTTR (resolución)', value: m.mttr.avgMinutes === null ? 's/d' : fmt(m.mttr.avgMinutes), status: m.mttr.avgMinutes !== null && m.mttr.avgMinutes <= 480 ? 'good' : 'warn', source: 'real' },
          { label: 'MTTA (1ª respuesta)', value: m.mtta.avgMinutes === null ? 's/d' : fmt(m.mtta.avgMinutes), status: m.mtta.avgMinutes !== null && m.mtta.avgMinutes <= 240 ? 'good' : 'warn', source: 'real' },
          fpRateKpi,
        ],
      });
    }
  } catch (err) { logger.warn({ err }, 'risk: deteccion'); domains.push(pending('deteccion', 'Detectar y responder', '¿Reducimos el tiempo en que una amenaza activa está sin contener?')); }

  // ---------- 2. Reducir la exposición ----------
  try {
    const v = await getVulnerabilities();
    const crit = v.resumen.critical, high = v.resumen.high;
    let cis = 0;
    try { cis = (await getSca()).resumen.scorePromedio; } catch { /* opcional */ }
    // Postura combina vulnerabilidades (peso) y hardening CIS.
    const vulnPosture = clamp(100 - crit * 1.5 - high * 0.05);
    const posture = clamp(vulnPosture * 0.6 + cis * 0.4);
    domains.push({
      key: 'exposicion', title: 'Reducir la exposición al riesgo',
      businessQuestion: '¿Estamos disminuyendo la probabilidad de una interrupción?',
      status: st(posture, 70, 45), posture,
      kpis: [
        { label: 'Vulnerabilidades críticas', value: String(crit), status: crit === 0 ? 'good' : crit <= 10 ? 'warn' : 'bad', source: 'real' },
        { label: 'Vulnerabilidades altas', value: String(high), status: high <= 20 ? 'good' : high <= 200 ? 'warn' : 'bad', source: 'real' },
        { label: 'Hardening CIS (prom.)', value: cis ? `${cis}%` : 's/d', status: cis >= 70 ? 'good' : cis >= 40 ? 'warn' : 'bad', source: 'real' },
        { label: 'Tiempo prom. de remediación', value: '—', status: 'pending', source: 'pending', note: 'Requiere marcar remediación por CVE (proceso)' },
      ],
    });
  } catch (err) { logger.warn({ err }, 'risk: exposicion'); domains.push(pending('exposicion', 'Reducir la exposición al riesgo', '¿Estamos disminuyendo la probabilidad de una interrupción?')); }

  // ---------- 3. Proteger identidades y accesos ----------
  try {
    const rows = await query<{ total: string; con_mfa: string; admins: string; admins_mfa: string }>(
      `SELECT count(*) total,
              count(*) FILTER (WHERE totp_enabled) con_mfa,
              count(*) FILTER (WHERE r.name = 'admin') admins,
              count(*) FILTER (WHERE r.name = 'admin' AND totp_enabled) admins_mfa
         FROM users u JOIN roles r ON r.id = u.role_id WHERE u.is_active`
    );
    const t = Number(rows[0].total), mfa = Number(rows[0].con_mfa);
    const socMfaPct = t ? clamp((mfa / t) * 100) : 0;
    // La postura de identidad de la ORGANIZACIÓN (MFA de los usuarios de GVM en
    // M365/Azure AD) requiere el informe de métodos de autenticación de Microsoft
    // Graph, que aún no está conectado. El único dato de MFA disponible es el 2FA
    // de la CONSOLA del SOC (tabla de operadores de HexWatch): un control interno
    // real, pero que NO representa la postura de GVM. Por eso el dominio queda
    // "sin fuente" (posture=null) y no puntúa el índice con un 0 falso; antes esto
    // reportaba "0% MFA (0/1)" y hundía el índice global a "crítico".
    domains.push({
      key: 'identidades', title: 'Proteger identidades y accesos',
      businessQuestion: '¿Están protegidos los accesos a los sistemas críticos?',
      status: 'pending', posture: null,
      kpis: [
        { label: 'MFA en M365 (usuarios)', value: '—', status: 'pending', source: 'pending', note: 'Requiere el informe de métodos de autenticación de Microsoft Graph (Reports.Read.All)' },
        { label: 'MFA en cuentas privilegiadas (M365)', value: '—', status: 'pending', source: 'pending', note: 'Requiere Microsoft Graph' },
        { label: '2FA en la consola HexWatch', value: `${socMfaPct}% (${mfa}/${t})`, status: st(socMfaPct, 100, 50), source: 'real', note: 'Control interno: 2FA de los operadores del SOC. No representa la postura de identidad de GVM.' },
        { label: 'Revisiones de acceso', value: '—', status: 'pending', source: 'pending', note: 'Requiere proceso/registro de revisión' },
      ],
    });
  } catch (err) { logger.warn({ err }, 'risk: identidades'); domains.push(pending('identidades', 'Proteger identidades y accesos', '¿Están protegidos los accesos a los sistemas críticos?')); }

  // ---------- 4. Fortalecer el factor humano (campañas de phishing) ----------
  try {
    const hf = await getHumanFactor();
    if (!hf) {
      domains.push({
        key: 'factor_humano', title: 'Fortalecer el factor humano',
        businessQuestion: '¿Nuestra gente es una defensa o un riesgo?',
        status: 'pending', posture: null,
        kpis: [
          { label: 'Tasa de clics en phishing', value: '—', status: 'pending', source: 'pending', note: 'Registra una campaña en Factor Humano' },
          { label: 'Reportado por usuarios', value: '—', status: 'pending', source: 'pending', note: 'Registra una campaña en Factor Humano' },
          { label: '% empleados capacitados', value: '—', status: 'pending', source: 'pending', note: 'Registra una campaña en Factor Humano' },
        ],
      });
    } else {
      domains.push({
        key: 'factor_humano', title: 'Fortalecer el factor humano',
        businessQuestion: '¿Nuestra gente es una defensa o un riesgo?',
        status: st(hf.posture, 75, 50), posture: hf.posture,
        kpis: [
          { label: 'Tasa de clics en phishing', value: `${hf.clickRate}%`, status: hf.clickRate <= 5 ? 'good' : hf.clickRate <= 15 ? 'warn' : 'bad', source: 'real' },
          { label: 'Reportado por usuarios', value: `${hf.reportRate}%`, status: hf.reportRate >= 30 ? 'good' : hf.reportRate >= 10 ? 'warn' : 'bad', source: 'real' },
          { label: '% empleados capacitados', value: `${hf.trainedPct}%`, status: hf.trainedPct >= 80 ? 'good' : hf.trainedPct >= 50 ? 'warn' : 'bad', source: 'real' },
          { label: 'Campañas (12 m)', value: `${hf.campaigns}`, status: 'good', source: 'real' },
        ],
      });
    }
  } catch (err) { logger.warn({ err }, 'risk: factor_humano'); domains.push(pending('factor_humano', 'Fortalecer el factor humano', '¿Nuestra gente es una defensa o un riesgo?')); }

  // ---------- 5. Resiliencia del negocio ----------
  try {
    const backups = await listBackups();
    const last = backups[0];
    const lastAgeH = last?.createdAt ? (Date.now() - new Date(last.createdAt).getTime()) / 3600000 : Infinity;
    // Cobertura honesta: una estación apagada fuera de horario NO es una caída.
    // Solo cuentan como no disponibles los problemas reales (servidor caído, agente
    // que nunca conectó, o sin reportar >7 días) = needsAttention en la clasificación
    // ya afinada. Antes esto reportaba 40% (8/20) contando estaciones apagadas.
    const allAgents = await getAgents(500).catch(() => []);
    const totalAg = allAgents.length;
    const problemas = allAgents.filter((a) => a.needsAttention).length;
    const disponibles = totalAg - problemas;
    const avail = totalAg ? clamp((disponibles / totalAg) * 100) : 100;
    const backupOk = backups.length > 0 && lastAgeH <= 48;
    const posture = clamp(avail * 0.6 + (backupOk ? 40 : backups.length ? 20 : 0));
    domains.push({
      key: 'resiliencia', title: 'Mejorar la resiliencia del negocio',
      businessQuestion: '¿Podemos recuperar la operación si sufrimos un ataque?',
      status: st(posture, 85, 60), posture,
      kpis: [
        { label: 'Respaldos disponibles', value: `${backups.length}`, status: backups.length > 0 ? 'good' : 'bad', source: 'real', note: 'Restauración validada' },
        { label: 'Último respaldo', value: Number.isFinite(lastAgeH) ? fmt(lastAgeH * 60) : 'nunca', status: lastAgeH <= 48 ? 'good' : 'warn', source: 'real' },
        { label: 'Cobertura de agentes', value: `${avail}% (${disponibles}/${totalAg})`, status: st(avail, 95, 80), source: 'real', note: 'Solo cuentan caídas reales; estaciones apagadas fuera de horario no restan.' },
        { label: 'Cumplimiento RTO/RPO', value: '—', status: 'pending', source: 'pending', note: 'Requiere prueba de recuperación (DR) formal' },
      ],
    });
  } catch (err) { logger.warn({ err }, 'risk: resiliencia'); domains.push(pending('resiliencia', 'Mejorar la resiliencia del negocio', '¿Podemos recuperar la operación si sufrimos un ataque?')); }

  // ---------- 6. Gobierno y cumplimiento ----------
  try {
    let cis = 0;
    try { cis = (await getSca()).resumen.scorePromedio; } catch { /* opcional */ }
    const inc = await query<{ total: string; resueltos: string; abiertos: string }>(
      `SELECT count(*) total,
              count(*) FILTER (WHERE status IN ('resuelto','cerrado')) resueltos,
              count(*) FILTER (WHERE status IN ('abierto','en_curso')) abiertos
         FROM incidents`
    );
    const total = Number(inc[0].total), resueltos = Number(inc[0].resueltos), abiertos = Number(inc[0].abiertos);
    const mitigadosPct = total ? clamp((resueltos / total) * 100) : 100;
    const posture = clamp(cis * 0.6 + mitigadosPct * 0.4);
    domains.push({
      key: 'gobierno', title: 'Demostrar gobierno y cumplimiento',
      businessQuestion: '¿Cada control implementado reduce un riesgo relevante?',
      status: st(posture, 70, 45), posture,
      kpis: [
        { label: 'Controles CIS implementados', value: cis ? `${cis}%` : 's/d', status: cis >= 70 ? 'good' : cis >= 40 ? 'warn' : 'bad', source: 'real' },
        { label: '% riesgos mitigados (incidentes)', value: `${mitigadosPct}% (${resueltos}/${total})`, status: st(mitigadosPct, 80, 50), source: 'real' },
        { label: 'Excepciones/riesgos abiertos', value: String(abiertos), status: abiertos === 0 ? 'good' : abiertos <= 5 ? 'warn' : 'bad', source: 'real' },
      ],
    });
  } catch (err) { logger.warn({ err }, 'risk: gobierno'); domains.push(pending('gobierno', 'Demostrar gobierno y cumplimiento', '¿Cada control implementado reduce un riesgo relevante?')); }

  // ---------- Índice compuesto (solo dominios medibles, ponderado) ----------
  const weights: Record<string, number> = { exposicion: 0.30, identidades: 0.25, deteccion: 0.20, resiliencia: 0.15, gobierno: 0.10 };
  let sum = 0, wsum = 0, measured = 0;
  for (const d of domains) {
    if (d.posture !== null && weights[d.key]) {
      sum += d.posture * weights[d.key]; wsum += weights[d.key]; measured++;
    }
  }
  const score = wsum ? clamp(sum / wsum) : 0;
  const { level, label } = levelFromScore(score);

  return {
    generatedAt: new Date().toISOString(),
    index: { score, level, label, measuredDomains: measured },
    overallQuestion: '¿Cada peso invertido en seguridad está reduciendo un riesgo relevante?',
    domains,
  };
}

function fmt(min: number): string {
  if (min < 60) return `${Math.round(min)} min`;
  if (min < 1440) return `${(min / 60).toFixed(1)} h`;
  return `${(min / 1440).toFixed(1)} d`;
}
function pending(key: string, title: string, businessQuestion: string): Domain {
  return { key, title, businessQuestion, status: 'pending', posture: null, kpis: [{ label: 'Sin datos', value: '—', status: 'pending', source: 'pending' }] };
}

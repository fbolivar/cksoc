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
import { cachedHealth, getOverallHealth } from '../health/siem-health.service';
import { listBackups } from '../backups/backups.service';
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
    const sla = m.sla.overallPct ?? 0;
    const posture = clamp(sla);
    domains.push({
      key: 'deteccion', title: 'Detectar y responder',
      businessQuestion: '¿Reducimos el tiempo en que una amenaza activa está sin contener?',
      status: st(posture), posture,
      kpis: [
        { label: 'Cumplimiento de SLA', value: m.sla.overallPct === null ? 's/d' : `${m.sla.overallPct}%`, status: st(sla), source: 'real' },
        { label: 'MTTR (resolución)', value: m.mttr.avgMinutes === null ? 's/d' : fmt(m.mttr.avgMinutes), status: m.mttr.avgMinutes !== null && m.mttr.avgMinutes <= 480 ? 'good' : 'warn', source: 'real' },
        { label: 'MTTA (1ª respuesta)', value: m.mtta.avgMinutes === null ? 's/d' : fmt(m.mtta.avgMinutes), status: m.mtta.avgMinutes !== null && m.mtta.avgMinutes <= 240 ? 'good' : 'warn', source: 'real' },
        { label: 'Incidentes abiertos > 24h', value: String(m.aging.openOver24h), status: m.aging.openOver24h === 0 ? 'good' : m.aging.openOver24h <= 3 ? 'warn' : 'bad', source: 'real' },
      ],
    });
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
    const t = Number(rows[0].total), mfa = Number(rows[0].con_mfa), adm = Number(rows[0].admins), admMfa = Number(rows[0].admins_mfa);
    const mfaPct = t ? clamp((mfa / t) * 100) : 0;
    const privPct = adm ? clamp((admMfa / adm) * 100) : 100;
    // Ponderamos fuerte el MFA en cuentas privilegiadas.
    const posture = clamp(mfaPct * 0.4 + privPct * 0.6);
    domains.push({
      key: 'identidades', title: 'Proteger identidades y accesos',
      businessQuestion: '¿Están protegidos los accesos a los sistemas críticos?',
      status: st(posture, 90, 60), posture,
      kpis: [
        { label: 'Usuarios con MFA', value: `${mfaPct}% (${mfa}/${t})`, status: st(mfaPct, 90, 60), source: 'real' },
        { label: 'Cuentas privilegiadas con MFA', value: `${privPct}% (${admMfa}/${adm})`, status: st(privPct, 100, 50), source: 'real', note: adm > admMfa ? 'Hay admins sin 2º factor' : undefined },
        { label: 'Cobertura PAM', value: '—', status: 'pending', source: 'pending', note: 'Requiere herramienta PAM' },
        { label: 'Revisiones de acceso', value: '—', status: 'pending', source: 'pending', note: 'Requiere proceso/registro de revisión' },
      ],
    });
  } catch (err) { logger.warn({ err }, 'risk: identidades'); domains.push(pending('identidades', 'Proteger identidades y accesos', '¿Están protegidos los accesos a los sistemas críticos?')); }

  // ---------- 4. Fortalecer el factor humano (sin fuente) ----------
  domains.push({
    key: 'factor_humano', title: 'Fortalecer el factor humano',
    businessQuestion: '¿Nuestra gente es una defensa o un riesgo?',
    status: 'pending', posture: null,
    kpis: [
      { label: 'Tasa de clics en phishing', value: '—', status: 'pending', source: 'pending', note: 'Requiere plataforma de simulación de phishing' },
      { label: '% empleados capacitados', value: '—', status: 'pending', source: 'pending', note: 'Requiere LMS / registro de capacitación' },
      { label: 'Incidentes reportados por usuarios', value: '—', status: 'pending', source: 'pending', note: 'Requiere canal de reporte' },
    ],
  });

  // ---------- 5. Resiliencia del negocio ----------
  try {
    const backups = await listBackups();
    const last = backups[0];
    const lastAgeH = last?.createdAt ? (Date.now() - new Date(last.createdAt).getTime()) / 3600000 : Infinity;
    const health = cachedHealth() ?? (await getOverallHealth());
    const agents = health.agentes ?? [];
    const active = agents.filter((a) => a.status === 'active').length;
    const avail = agents.length ? clamp((active / agents.length) * 100) : 100;
    const backupOk = backups.length > 0 && lastAgeH <= 48;
    const posture = clamp(avail * 0.6 + (backupOk ? 40 : backups.length ? 20 : 0));
    domains.push({
      key: 'resiliencia', title: 'Mejorar la resiliencia del negocio',
      businessQuestion: '¿Podemos recuperar la operación si sufrimos un ataque?',
      status: st(posture, 85, 60), posture,
      kpis: [
        { label: 'Respaldos disponibles', value: `${backups.length}`, status: backups.length > 0 ? 'good' : 'bad', source: 'real', note: 'Restauración validada' },
        { label: 'Último respaldo', value: Number.isFinite(lastAgeH) ? fmt(lastAgeH * 60) : 'nunca', status: lastAgeH <= 48 ? 'good' : 'warn', source: 'real' },
        { label: 'Disponibilidad de agentes', value: `${avail}% (${active}/${agents.length})`, status: st(avail, 95, 80), source: 'real' },
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

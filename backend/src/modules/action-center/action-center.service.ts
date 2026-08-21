/**
 * Centro de Acción: una sola cola priorizada que reúne, de todos los módulos,
 * lo que requiere una acción del operador — con la acción de un clic al lado.
 * Convierte "revisar 30 módulos" en "atender una bandeja". Reutiliza los motores
 * de recomendación y las acciones ya existentes (bloqueo, deshabilitar, escalar,
 * triage, aprobar SOAR), todas con lista blanca/rol/auditoría en su propio módulo.
 */
import { getIdentityRecommendations } from '../identity/identity.service';
import { getIncidents } from '../response/incidents.service';
import { getAssetRadar } from '../overview/radar.service';
import { runHelper } from '../velociraptor/velociraptor.helper';
import { slaBreachedIncidents } from '../incidents/sla.service';
import { listEvents } from '../soar/soar.service';

export type Severity = 'alta' | 'media' | 'baja';
export type ActionKind = 'block_ip' | 'disable_m365' | 'delete_m365' | 'escalate' | 'collect' | 'soar_approve' | 'soar_reject';

export interface ActionButton { kind: ActionKind; label: string; danger?: boolean; params: Record<string, string> }
export interface ActionItem {
  key: string;
  source: 'soar' | 'identidad' | 'red' | 'endpoint' | 'incidente';
  severity: Severity;
  title: string;
  subject: string;
  reason: string;
  meta: { label: string; value: string }[];
  actions: ActionButton[];
}

const RANK: Record<Severity, number> = { alta: 0, media: 1, baja: 2 };
const SRC_RANK: Record<ActionItem['source'], number> = { soar: 0, red: 1, identidad: 2, incidente: 3, endpoint: 4 };

interface VeloClient { host?: string }

export async function getActionQueue(): Promise<{ generatedAt: string; total: number; bySeverity: Record<Severity, number>; items: ActionItem[] }> {
  const items: ActionItem[] = [];

  const [ident, net, radar, veloList, sla, soar] = await Promise.allSettled([
    getIdentityRecommendations(),
    getIncidents(24, 20),
    getAssetRadar(),
    runHelper(['list']),
    slaBreachedIncidents(),
    listEvents(200),
  ]);

  // 1) SOAR — acciones automáticas pendientes de aprobación (máxima prioridad).
  if (soar.status === 'fulfilled') {
    for (const ev of soar.value) {
      if (ev.status !== 'pending') continue;
      items.push({
        key: `soar:${ev.id}`, source: 'soar', severity: 'alta',
        title: `SOAR propone: ${ev.action}`,
        subject: ev.entity,
        reason: `Regla "${ev.rule_name ?? 'automatización'}" disparó una acción sobre ${ev.entity} y espera tu aprobación.`,
        meta: [{ label: 'acción', value: ev.action }, { label: 'regla', value: ev.rule_name ?? '—' }],
        actions: [
          { kind: 'soar_approve', label: 'Aprobar', params: { id: ev.id } },
          { kind: 'soar_reject', label: 'Rechazar', danger: true, params: { id: ev.id } },
        ],
      });
    }
  }

  // 2) Red — IPs atacantes públicas NO bloqueadas con mala reputación / severidad alta.
  if (net.status === 'fulfilled') {
    for (const inc of net.value) {
      if (inc.blocked) continue;
      const score = inc.reputation?.abuseScore ?? 0;
      const sev: Severity = score >= 90 || inc.severityMax >= 12 ? 'alta' : score >= 40 || inc.severityMax >= 10 ? 'media' : 'baja';
      if (sev === 'baja') continue; // no saturar con ruido leve
      items.push({
        key: `red:${inc.ip}`, source: 'red', severity: sev,
        title: 'IP atacante sin bloquear',
        subject: inc.ip,
        reason: `${inc.attempts} eventos${score ? `, reputación AbuseIPDB ${score}/100` : ''}${inc.country ? `, ${inc.country}` : ''}. ${inc.ruleDescription || 'Actividad ofensiva'}.`,
        meta: [{ label: 'intentos', value: String(inc.attempts) }, { label: 'reputación', value: String(score) }, { label: 'país', value: inc.country }],
        actions: [{ kind: 'block_ip', label: 'Bloquear en FortiGate', danger: true, params: { ip: inc.ip } }],
      });
    }
  }

  // 3) Identidad — recomendaciones con acción (higiene de invitados + amenazas signin).
  if (ident.status === 'fulfilled') {
    for (const r of ident.value.items) {
      const acts: ActionButton[] = [];
      if (r.actions.includes('disable')) acts.push({ kind: 'disable_m365', label: 'Deshabilitar', params: { upn: r.upn } });
      if (r.actions.includes('delete')) acts.push({ kind: 'delete_m365', label: 'Eliminar', danger: true, params: { upn: r.upn } });
      if (!acts.length) continue;
      items.push({
        key: `ident:${r.upn}`, source: 'identidad', severity: r.severity,
        title: r.title, subject: r.mail || r.upn, reason: r.reason,
        meta: r.meta, actions: acts,
      });
    }
  }

  // 4) Incidentes con SLA vencido — escalar.
  if (sla.status === 'fulfilled') {
    for (const b of sla.value) {
      const sev: Severity = b.severity === 'critica' || b.severity === 'alta' ? 'alta' : b.severity === 'media' ? 'media' : 'baja';
      items.push({
        key: `inc:${b.id}`, source: 'incidente', severity: sev,
        title: 'Incidente con SLA vencido', subject: b.title,
        reason: `${b.resolveBreached ? 'Resolución' : 'Reconocimiento'} vencido; asignado a ${b.assigneeName ?? 'nadie'}. Escala al on-call.`,
        meta: [{ label: 'severidad', value: b.severity }, { label: 'estado', value: b.status }],
        actions: [{ kind: 'escalate', label: 'Escalar', params: { id: b.id } }],
      });
    }
  }

  // 5) Endpoints de alto riesgo con cliente Velociraptor — triage forense.
  if (radar.status === 'fulfilled' && veloList.status === 'fulfilled') {
    const clients = Array.isArray(veloList.value) ? (veloList.value as VeloClient[]) : [];
    const veloHosts = new Set(clients.map((c) => String(c?.host ?? '').toLowerCase()).filter(Boolean));
    for (const a of radar.value.assets) {
      if (a.band !== 'critico' && a.band !== 'alto') continue;
      if (!veloHosts.has(a.name.toLowerCase())) continue;
      items.push({
        key: `ep:${a.name}`, source: 'endpoint', severity: a.band === 'critico' ? 'alta' : 'media',
        title: 'Host de alto riesgo', subject: a.name,
        reason: `Riesgo ${a.risk}/100${a.criticalVulns ? `, ${a.criticalVulns} vulns críticas` : ''}${a.status !== 'active' ? ', desconectado' : ''}. Lanza triage forense.`,
        meta: [{ label: 'riesgo', value: String(a.risk) }, { label: 'IP', value: a.ip || '—' }],
        actions: [{ kind: 'collect', label: 'Investigar (triage)', params: { host: a.name } }],
      });
    }
  }

  items.sort((x, y) => RANK[x.severity] - RANK[y.severity] || SRC_RANK[x.source] - SRC_RANK[y.source]);
  const bySeverity: Record<Severity, number> = { alta: 0, media: 0, baja: 0 };
  for (const it of items) bySeverity[it.severity]++;
  return { generatedAt: new Date().toISOString(), total: items.length, bySeverity, items };
}

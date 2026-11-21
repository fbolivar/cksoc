/**
 * NOC — Monitoreo de disponibilidad. Admin/analista.
 *   GET    /api/noc/overview
 *   GET    /api/noc/report?days=30     (uptime % histórico por objetivo)
 *   POST   /api/noc/targets            { name, host, kind?, port?, path?, grupo?, snmpEnabled?, snmpCommunity? }
 *   PUT    /api/noc/targets/:id        { enabled }
 *   PUT    /api/noc/targets/:id/snmp   { enabled, community? }
 *   DELETE /api/noc/targets/:id
 *   POST   /api/noc/check              (corre los chequeos ahora)
 * Scheduler: chequea cada NOC_CRON (def. cada 2 min) y avisa por Telegram (CKAgentico)
 * cuando un objetivo cae o se recupera (gateado por licencia). Las caídas de equipos
 * del cliente generan además un instructivo paso a paso para el soporte en sitio (Ricardo).
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { sendTelegram } from '../notifications/telegram.service';
import { getOverview, getReport, getTrend, addTarget, setEnabled, setSnmp, deleteTarget, runChecks, ensureNocSchema, isNocEnabled, SOC_GROUPS } from './noc.service';
import { getAgentsSummary, getAgents } from '../wazuh/agents.service';

export const nocRouter = Router();
nocRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en NOC');
  res.status(500).json({ error: 'Error interno del servidor' });
}

nocRouter.get('/overview', canManage, async (_req, res) => { try { res.json(await getOverview()); } catch (e) { handle(e, res); } });
nocRouter.get('/report', canManage, async (req, res) => {
  try { const days = req.query.days != null ? Number(req.query.days) : 30; res.json(await getReport(Number.isFinite(days) ? days : 30)); } catch (e) { handle(e, res); }
});
nocRouter.get('/trend', canManage, async (req, res) => {
  try { const days = req.query.days != null ? Number(req.query.days) : 14; res.json(await getTrend(Number.isFinite(days) ? days : 14)); } catch (e) { handle(e, res); }
});
// Estado de agentes Wazuh (reutiliza wazuh/agents.service). Tolerante a fallo de la API.
nocRouter.get('/agents', canManage, async (_req, res) => {
  try {
    const [summary, list] = await Promise.all([getAgentsSummary().catch(() => null), getAgents(100).catch(() => [])]);
    const agents = list.filter((a) => a.id !== '000').map((a) => ({ id: a.id, name: a.name, ip: a.ip, status: a.status, health: a.health, kind: a.kind, needsAttention: a.needsAttention, staleDays: a.staleDays }));
    res.json({ ok: summary != null, summary, agents });
  } catch (e) { handle(e, res); }
});
nocRouter.post('/targets', canManage, async (req, res) => {
  try {
    const name = String(req.body?.name ?? '').trim(); const host = String(req.body?.host ?? '').trim();
    if (!name || !host) { res.status(400).json({ error: 'name y host requeridos' }); return; }
    const kind = req.body?.kind; const port = req.body?.port != null ? Number(req.body.port) : null;
    if (kind === 'tcp' && (!port || port < 1 || port > 65535)) { res.status(400).json({ error: 'puerto inválido para TCP' }); return; }
    const id = await addTarget({
      name, host, kind, port, path: req.body?.path ? String(req.body.path) : null,
      grupo: req.body?.grupo ? String(req.body.grupo) : undefined,
      snmpEnabled: req.body?.snmpEnabled === true || req.body?.snmpEnabled === 'true',
      snmpCommunity: req.body?.snmpCommunity ? String(req.body.snmpCommunity) : null,
    });
    res.status(201).json({ id });
  } catch (e) { handle(e, res); }
});
nocRouter.put('/targets/:id', canManage, async (req, res) => {
  try { await setEnabled(req.params.id, req.body?.enabled === true || req.body?.enabled === 'true'); res.json({ ok: true }); } catch (e) { handle(e, res); }
});
nocRouter.put('/targets/:id/snmp', canManage, async (req, res) => {
  try {
    const enabled = req.body?.enabled === true || req.body?.enabled === 'true';
    await setSnmp(req.params.id, enabled, req.body?.community ? String(req.body.community) : null);
    res.json({ ok: true });
  } catch (e) { handle(e, res); }
});
nocRouter.delete('/targets/:id', canManage, async (req, res) => {
  try { await deleteTarget(req.params.id); res.json({ ok: true }); } catch (e) { handle(e, res); }
});
nocRouter.post('/check', canManage, async (_req, res) => {
  try { const r = await runChecks(); res.json({ ok: true, ...r }); } catch (e) { handle(e, res); }
});
nocRouter.post('/digest', canManage, async (_req, res) => {
  try { await nocDigest(); res.json({ ok: true }); } catch (e) { handle(e, res); }
});

type Trans = { name: string; host: string; grupo: string; to: string; downMin: number | null };

// Aviso técnico al SOC + instructivo amable a soporte en sitio (Ricardo) para equipos del cliente.
async function alertTransitions(trans: Trans[]): Promise<void> {
  if (!trans.length || !env.TELEGRAM_CHAT_ID) return;
  const down = trans.filter((t) => t.to === 'down');
  const up = trans.filter((t) => t.to === 'up');

  // 1) Resumen técnico al SOC
  const L: string[] = ['📡 CKAgentico · NOC — cambios de disponibilidad', ''];
  for (const t of down) L.push(`🔴 ${t.name} (${t.host}) NO responde — caído.`);
  for (const t of up) L.push(`🟢 ${t.name} (${t.host}) se recuperó${t.downMin != null ? ` (estuvo caído ~${t.downMin} min)` : ''}.`);
  const clientDown = down.filter((t) => !SOC_GROUPS.includes(t.grupo));
  if (clientDown.length) L.push('', `👷 ${clientDown.length} equipo(s) del cliente caído(s) → se envió instructivo al soporte en sitio (Ricardo).`);
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);

  // 2) Instructivo a Ricardo (soporte en sitio) solo para equipos del cliente caídos.
  if (clientDown.length) {
    const soporteChat = process.env.SOPORTE_TELEGRAM_CHAT_ID || process.env.RICARDO_TELEGRAM_CHAT_ID || env.TELEGRAM_CHAT_ID;
    for (const t of clientDown) {
      const R: string[] = [
        `🔧 Hola Ricardo 👋 — necesitamos tu apoyo en sitio.`,
        ``,
        `El equipo *${t.name}* (dirección ${t.host}) dejó de responder y puede estar apagado o desconectado.`,
        ``,
        `Cuando puedas, revisá con calma estos pasos:`,
        `1️⃣ Ubicá el equipo físicamente y verificá que esté *encendido* (luces/ventilador).`,
        `2️⃣ Revisá que el *cable de red* esté bien conectado a ambos extremos (equipo y pared/switch). Probá reconectarlo.`,
        `3️⃣ Confirmá que el *toma de corriente* tenga energía (probá otro aparato o enchufe).`,
        `4️⃣ Si usa WiFi, verificá que esté conectado a la red correcta.`,
        `5️⃣ Si todo se ve bien pero sigue sin responder, *reiniciá* el equipo y esperá 2–3 minutos.`,
        ``,
        `Avisanos por aquí cómo te fue 🙏. ¡Gracias por el apoyo!`,
      ];
      await sendTelegram([soporteChat], R.join('\n')).catch(() => undefined); // Markdown (negritas)
    }
  }
}

// Resumen periódico de disponibilidad del NOC a Telegram (monitoreo de estado),
// además de las alertas por transición. Gateado por licencia (sendTelegram).
async function nocDigest(): Promise<void> {
  if (!env.TELEGRAM_CHAT_ID) return;
  const ov = await getOverview();
  const k = ov.kpis;
  const all = ov.grupos.flatMap((g) => g.targets).filter((t) => t.enabled);
  const down = all.filter((t) => t.status === 'down');
  const snmp = all.filter((t) => t.snmp_enabled);
  const hot = snmp.filter((t) => (t.cpu_pct != null && t.cpu_pct >= 85) || (t.mem_pct != null && t.mem_pct >= 90));
  const L: string[] = ['📡 CKAgentico · NOC — Resumen de disponibilidad', ''];
  L.push(`🗓 ${new Date().toLocaleString('es-CO', { hour12: false })}`);
  L.push(down.length ? `Estado: 🔴 ${down.length} equipo(s) caído(s)` : 'Estado: 🟢 OPERATIVO');
  L.push(`Objetivos: ${k.up}/${k.total} arriba · Uptime 30d prom: ${k.avgUptime30 != null ? k.avgUptime30.toFixed(2) + '%' : '—'} · Latencia prom: ${k.avgLatency ?? '—'} ms`);
  if (down.length) { L.push('', '🔴 Caídos:'); for (const t of down) L.push(` • ${t.name} (${t.host})`); }
  if (hot.length) {
    L.push('', '⚠ Recursos altos:');
    for (const t of hot) {
      const p: string[] = [];
      if (t.cpu_pct != null && t.cpu_pct >= 85) p.push(`CPU ${t.cpu_pct}%`);
      if (t.mem_pct != null && t.mem_pct >= 90) p.push(`RAM ${t.mem_pct}%`);
      L.push(` • ${t.name}: ${p.join(' · ')}`);
    }
  }
  if (!down.length && !hot.length) L.push('', `✅ Todo operativo · ${all.length} objetivos monitoreados (${snmp.length} con SNMP).`);
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
}

/** Digest programado del NOC (resumen de disponibilidad a Telegram). */
export function startNocDigest(): void {
  const spec = process.env.NOC_DIGEST_CRON || '0 7,19 * * *'; // 7:00 y 19:00 por defecto
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de NOC digest inválido'); return; }
  cron.schedule(spec, () => { void nocDigest().catch((e) => logger.error({ err: e }, 'NOC digest: error')); });
  logger.info(`📡 NOC digest a Telegram activo (${spec})`);
}

/** Scheduler del NOC: chequeo periódico + aviso por transición. */
export function startNocScheduler(): void {
  if (!isNocEnabled()) { logger.info('📡 NOC desactivado (NOC_ENABLED=false)'); return; }
  void ensureNocSchema().catch((e) => logger.error({ err: e }, 'NOC: no se pudo preparar el esquema'));
  const spec = process.env.NOC_CRON || '*/2 * * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de NOC inválido'); return; }
  cron.schedule(spec, async () => {
    try { const r = await runChecks(); if (r.transitions.length) { logger.info({ transiciones: r.transitions.length }, '📡 NOC: cambios de disponibilidad'); await alertTransitions(r.transitions); } }
    catch (e) { logger.error({ err: e }, 'NOC: error en chequeo programado'); }
  });
  setTimeout(() => { void runChecks().catch(() => undefined); }, 15_000); // primera pasada al arranque
  logger.info(`📡 NOC activo (${spec})`);
  startNocDigest(); // resumen periódico de disponibilidad a Telegram
}

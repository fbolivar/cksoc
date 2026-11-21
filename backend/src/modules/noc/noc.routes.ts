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
import { getOverview, getReport, addTarget, setEnabled, setSnmp, deleteTarget, runChecks, ensureNocSchema, isNocEnabled, SOC_GROUPS } from './noc.service';

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
}

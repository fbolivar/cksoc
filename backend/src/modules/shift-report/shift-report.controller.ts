/** Controladores del Parte de Estado (shift report). */
import type { Request, Response } from 'express';
import { z } from 'zod';
import { buildShiftReport, sendShiftReport, shiftChatIds, isInternalOnly } from './shift-report.service';
import { isTelegramConfigured } from '../notifications/telegram.service';
import { auditFromReq } from '../audit/audit.service';

const turnoSchema = z.object({ turno: z.enum(['am', 'pm']).optional() });

/** GET /api/shift-report/preview?turno=am|pm — HTML del parte (vista previa). */
export async function getPreview(req: Request, res: Response): Promise<void> {
  const turno = req.query.turno === 'am' || req.query.turno === 'pm' ? req.query.turno : undefined;
  try {
    const { html } = await buildShiftReport(turno);
    res.type('html').send(html);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Error generando la vista previa' });
  }
}

/** GET /api/shift-report/status — a quién se enviaría y si Telegram está listo. */
export function getStatus(_req: Request, res: Response): void {
  res.json({
    telegramReady: isTelegramConfigured(),
    internal: isInternalOnly(),
    destinatarios: shiftChatIds().length,
  });
}

/** POST /api/shift-report/send { turno? } — genera y envía por Telegram. */
export async function postSend(req: Request, res: Response): Promise<void> {
  const parsed = turnoSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos inválidos' });
    return;
  }
  try {
    const result = await sendShiftReport(parsed.data.turno);
    void auditFromReq(req, {
      actorId: req.user?.id,
      actorEmail: req.user?.email,
      action: 'shift_report_send',
      target: result.internal ? 'interno' : `cliente(${result.sentTo.length})`,
      result: 'ok',
      detail: { turno: parsed.data.turno ?? 'auto', internal: result.internal, filename: result.filename },
    });
    res.json({ ok: true, ...result });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Error enviando el parte';
    void auditFromReq(req, {
      actorId: req.user?.id,
      actorEmail: req.user?.email,
      action: 'shift_report_send',
      result: 'fail',
      detail: { error: msg },
    });
    res.status(500).json({ error: msg });
  }
}

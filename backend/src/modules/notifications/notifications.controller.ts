/**
 * Controladores del modulo de notificaciones.
 */
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  listRules,
  getRule,
  createRule,
  updateRule,
  deleteRule,
  type RuleInput,
} from './rules.service';
import { channelStatus, testSend, recentLog } from './notify.service';
import { evaluateRules } from './evaluator';
import { getSettings, updateSettings, dailyStatus, immediateEmail, sendCapped } from './notify.engine';
import { sendDailyDigest } from './digest.service';
import { verifyEmail } from './email.service';
import { verifyTelegram } from './telegram.service';
import { HttpError } from '../auth/auth.service';

const ruleSchema = z.object({
  name: z.string().min(2, 'Nombre requerido'),
  description: z.string().optional(),
  minLevel: z.number().int().min(0).max(15),
  ruleGroups: z.array(z.string()).default([]),
  threshold: z.number().int().min(1).max(100000),
  windowMinutes: z.number().int().min(1).max(1440),
  cooldownMinutes: z.number().int().min(0).max(1440),
  channels: z.array(z.enum(['email', 'telegram'])).default([]),
  emailRecipients: z.array(z.string().email()).default([]),
  telegramChatIds: z.array(z.string()).default([]),
  enabled: z.boolean().default(true),
});

export async function getRules(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ rules: await listRules(), channels: channelStatus() });
  } catch (err) {
    handle(err, res);
  }
}

export async function postRule(req: Request, res: Response): Promise<void> {
  const parsed = ruleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const rule = await createRule(parsed.data as RuleInput, req.user!.id);
    res.status(201).json({ rule });
  } catch (err) {
    handle(err, res);
  }
}

export async function putRule(req: Request, res: Response): Promise<void> {
  const parsed = ruleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const rule = await updateRule(req.params.id, parsed.data as RuleInput);
    res.json({ rule });
  } catch (err) {
    handle(err, res);
  }
}

export async function removeRule(req: Request, res: Response): Promise<void> {
  try {
    await deleteRule(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

export async function getOneRule(req: Request, res: Response): Promise<void> {
  try {
    res.json({ rule: await getRule(req.params.id) });
  } catch (err) {
    handle(err, res);
  }
}

const testSchema = z.object({
  channel: z.enum(['email', 'telegram']),
  target: z.string().min(1),
});

export async function postTest(req: Request, res: Response): Promise<void> {
  const parsed = testSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos' });
    return;
  }
  try {
    await testSend(parsed.data.channel, parsed.data.target);
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

/** Verifica la conexion de un canal (SMTP verify / Telegram getMe). */
export async function getChannelCheck(req: Request, res: Response): Promise<void> {
  try {
    if (req.params.channel === 'email') {
      await verifyEmail();
      res.json({ ok: true });
    } else if (req.params.channel === 'telegram') {
      const info = await verifyTelegram();
      res.json({ ok: true, bot: info.username });
    } else {
      res.status(400).json({ error: 'Canal invalido' });
    }
  } catch (err) {
    res.status(502).json({ ok: false, error: err instanceof Error ? err.message : 'error' });
  }
}

/** Fuerza una evaluacion inmediata de las reglas (util para pruebas). */
export async function postEvaluateNow(_req: Request, res: Response): Promise<void> {
  try {
    await evaluateRules();
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

export async function getLog(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ log: await recentLog(50) });
  } catch (err) {
    handle(err, res);
  }
}

// ---------------- Motor de correo: settings + digest ----------------

export async function getNotifySettings(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ settings: await getSettings(), daily: await dailyStatus(), channels: channelStatus() });
  } catch (err) {
    handle(err, res);
  }
}

const settingsSchema = z.object({
  recipients: z.array(z.string().email()).optional(),
  immediateEnabled: z.boolean().optional(),
  digestEnabled: z.boolean().optional(),
  digestHour: z.number().int().min(0).max(23).optional(),
});

export async function putNotifySettings(req: Request, res: Response): Promise<void> {
  const parsed = settingsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    res.json({ settings: await updateSettings(parsed.data) });
  } catch (err) {
    handle(err, res);
  }
}

export async function postSendDigest(_req: Request, res: Response): Promise<void> {
  try {
    const ok = await sendDailyDigest();
    res.json({ ok });
  } catch (err) {
    handle(err, res);
  }
}

/** Envia un correo de alerta CRITICA de muestra (valida la plantilla inmediata). */
export async function postTestImmediate(_req: Request, res: Response): Promise<void> {
  try {
    const settings = await getSettings();
    if (settings.recipients.length === 0) {
      res.status(400).json({ error: 'No hay destinatarios configurados' });
      return;
    }
    const sample = {
      level: 13,
      ruleId: '100031',
      description: 'Fuerza bruta IPsec XAuth (CORREO DE PRUEBA)',
      agent: 'pnncsrvncvwz01',
      origin: '161.18.175.59',
      geo: { country: 'Colombia', city: 'Bogotá' },
      reputation: { abuseScore: 42, totalReports: 14 },
      timestamp: new Date().toISOString(),
    };
    const { subject, html, text } = immediateEmail(sample);
    const ok = await sendCapped(settings.recipients, subject, html, text, {
      tipo: 'immediate', ruleId: '100031', ruleName: sample.description, origen: 'PRUEBA',
    });
    res.json({ ok });
  } catch (err) {
    handle(err, res);
  }
}

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Error en notificaciones:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
}

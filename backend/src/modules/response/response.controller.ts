/** Controladores del modulo de respuesta semi-automatica. */
import type { Request, Response } from 'express';
import { z } from 'zod';
import { block, unblock, listBlocked, history } from './response.service';
import { getIncidents } from './incidents.service';
import { checkReputation } from '../threatintel/abuseipdb.service';
import { geolocate } from '../geo/geoip.service';
import { verifyConnection, isFortigateConfigured } from './fortigate.service';
import { whitelistIps, canBlock, normalizeIp, isValidIpv4 } from './whitelist';
import { HttpError } from '../auth/auth.service';

// Validacion estricta de octetos (rechaza 999.999.999.999); consistente con canBlock.
const ipSchema = z.string().refine(isValidIpv4, 'IP invalida');

const blockSchema = z.object({
  ip: ipSchema,
  motivo: z.string().min(3, 'Indica un motivo'),
  alertaOrigenId: z.string().optional(),
});

function adminIpOf(req: Request): string {
  return normalizeIp((req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || '');
}

export async function postBlock(req: Request, res: Response): Promise<void> {
  const parsed = blockSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    await block({
      ip: parsed.data.ip,
      motivo: parsed.data.motivo,
      user: { id: req.user!.id, email: req.user!.email },
      adminIp: adminIpOf(req),
      alertaOrigenId: parsed.data.alertaOrigenId,
    });
    res.json({ ok: true, ip: parsed.data.ip });
  } catch (err) {
    handle(err, res);
  }
}

export async function postUnblock(req: Request, res: Response): Promise<void> {
  const parsed = z.object({ ip: ipSchema }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'IP invalida' });
    return;
  }
  try {
    await unblock({ ip: parsed.data.ip, user: { id: req.user!.id, email: req.user!.email } });
    res.json({ ok: true, ip: parsed.data.ip });
  } catch (err) {
    handle(err, res);
  }
}

export async function getBlocked(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ blocked: await listBlocked() });
  } catch (err) {
    handle(err, res);
  }
}

export async function getHistory(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ history: await history(150) });
  } catch (err) {
    handle(err, res);
  }
}

export async function getIncidentsCtrl(req: Request, res: Response): Promise<void> {
  const h = Number(req.query.hours);
  const hours = Number.isFinite(h) && h > 0 && h <= 720 ? Math.floor(h) : 24;
  const threatsOnly = req.query.threats !== '0'; // solo amenazas por defecto; ?threats=0 = ver todo
  try {
    res.json({ hours, threatsOnly, incidents: await getIncidents(hours, 15, threatsOnly) });
  } catch (err) {
    handle(err, res);
  }
}

/** Contexto de una IP: reputacion + geo + si seria bloqueable (para "Investigar"). */
export async function getReputation(req: Request, res: Response): Promise<void> {
  const ip = req.params.ip;
  if (!isValidIpv4(ip)) {
    res.status(400).json({ error: 'IP invalida' });
    return;
  }
  try {
    const [reputation, geo] = await Promise.all([checkReputation(ip), Promise.resolve(geolocate(ip))]);
    res.json({ ip, reputation, geo, blockable: canBlock(ip, adminIpOf(req)) });
  } catch (err) {
    handle(err, res);
  }
}

/** Estado del FortiGate y lista blanca (para la vista de respuesta). */
export async function getStatus(req: Request, res: Response): Promise<void> {
  const configured = isFortigateConfigured();
  let connection: { ok: boolean; group?: string; count?: number; error?: string } = { ok: false };
  if (configured) {
    try {
      const v = await verifyConnection();
      connection = { ok: true, group: v.group, count: v.count };
    } catch (err) {
      connection = { ok: false, error: err instanceof HttpError ? err.message : 'error' };
    }
  }
  res.json({ configured, connection, whitelist: whitelistIps(), adminIp: adminIpOf(req) });
}

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Error en response:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
}

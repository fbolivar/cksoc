/** Controladores de respaldos .bbg (todo rol admin). */
import type { Request, Response } from 'express';
import { createReadStream } from 'node:fs';
import { z } from 'zod';
import { logger } from '../../config/logger';
import { auditFromReq } from '../audit/audit.service';
import {
  createBackup, listBackups, deleteBackup, verifyBackup,
  backupFilePath, backupExists, HttpBackupError, getRecoveryPosture, restoreBackup,
  getNetCopyPublic, saveNetCopy, testNetCopy,
} from './backups.service';

export async function getBackups(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ backups: await listBackups() });
  } catch (err) {
    logger.error({ err }, 'No se pudo listar respaldos');
    res.status(500).json({ error: 'No se pudieron listar los respaldos' });
  }
}

export async function getPosture(_req: Request, res: Response): Promise<void> {
  try {
    res.json(await getRecoveryPosture());
  } catch (err) {
    logger.error({ err }, 'No se pudo calcular la postura de recuperación');
    res.status(500).json({ error: 'No se pudo calcular la postura de recuperación' });
  }
}

const createSchema = z.object({ note: z.string().max(200).optional() });

export async function postBackup(req: Request, res: Response): Promise<void> {
  const parsed = createSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos' });
    return;
  }
  try {
    const item = await createBackup({ origin: 'manual', note: parsed.data.note });
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'backup_create', target: item.id, result: 'ok' });
    res.status(201).json(item);
  } catch (err) {
    logger.error({ err }, 'Fallo la creacion de respaldo');
    res.status(500).json({ error: 'No se pudo crear el respaldo' });
  }
}

export async function downloadBackup(req: Request, res: Response): Promise<void> {
  try {
    const id = req.params.id;
    if (!(await backupExists(id))) {
      res.status(404).json({ error: 'Respaldo no encontrado' });
      return;
    }
    const p = backupFilePath(id);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${id}"`);
    createReadStream(p).pipe(res);
  } catch (err) {
    if (err instanceof HttpBackupError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'No se pudo descargar el respaldo' });
  }
}

export async function getBackupIntegrity(req: Request, res: Response): Promise<void> {
  try {
    if (!(await backupExists(req.params.id))) {
      res.status(404).json({ error: 'Respaldo no encontrado' });
      return;
    }
    res.json({ integrity: await verifyBackup(req.params.id) });
  } catch (err) {
    if (err instanceof HttpBackupError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'No se pudo verificar el respaldo' });
  }
}

export async function removeBackup(req: Request, res: Response): Promise<void> {
  try {
    // Guard: nunca dejar al cliente sin punto de recuperacion.
    const current = await listBackups();
    if (current.length <= 1) {
      res.status(409).json({ error: 'No se puede eliminar el ultimo respaldo disponible. Crea uno nuevo antes de borrar este para no quedar sin punto de recuperacion.' });
      return;
    }
    const ok = await deleteBackup(req.params.id);
    if (!ok) {
      res.status(404).json({ error: 'Respaldo no encontrado' });
      return;
    }
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'backup_delete', target: req.params.id, result: 'ok' });
    res.json({ ok: true });
  } catch (err) {
    if (err instanceof HttpBackupError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'No se pudo eliminar el respaldo' });
  }
}

export async function restoreBackupCtrl(req: Request, res: Response): Promise<void> {
  const id = req.params.id;
  const confirm = (req.body as { confirm?: string } | undefined)?.confirm;
  if (confirm !== id) {
    res.status(400).json({ error: 'Confirmacion invalida: debes confirmar el nombre exacto del respaldo.' });
    return;
  }
  try {
    const r = await restoreBackup(id);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'backup_restore', target: id, result: 'ok' });
    res.json({ ok: true, ...r });
  } catch (err) {
    if (err instanceof HttpBackupError) { res.status(err.status).json({ error: err.message }); return; }
    logger.error({ err }, 'Fallo la restauracion de respaldo');
    res.status(500).json({ error: 'No se pudo restaurar el respaldo' });
  }
}


const netCopySchema = z.object({
  enabled: z.boolean(),
  path: z.string().max(400),
  user: z.string().max(120).optional().default(''),
  domain: z.string().max(120).optional().default(''),
  password: z.string().max(200).optional(),
});

export async function getNetCopyCtrl(_req: Request, res: Response): Promise<void> {
  try { res.json(await getNetCopyPublic()); }
  catch { res.status(500).json({ error: 'No se pudo leer la configuracion de copia en red' }); }
}

export async function putNetCopyCtrl(req: Request, res: Response): Promise<void> {
  const parsed = netCopySchema.safeParse(req.body ?? {});
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos' }); return; }
  try {
    await saveNetCopy(parsed.data);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'backup_netcopy_config', target: parsed.data.path, result: 'ok' });
    res.json(await getNetCopyPublic());
  } catch { res.status(500).json({ error: 'No se pudo guardar la configuracion' }); }
}

export async function testNetCopyCtrl(req: Request, res: Response): Promise<void> {
  const parsed = netCopySchema.partial({ enabled: true }).safeParse(req.body ?? {});
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos' }); return; }
  try { res.json(await testNetCopy({ path: parsed.data.path ?? '', user: parsed.data.user ?? '', domain: parsed.data.domain ?? '', password: parsed.data.password })); }
  catch (e) { res.json({ ok: false, detail: (e as Error).message }); }
}

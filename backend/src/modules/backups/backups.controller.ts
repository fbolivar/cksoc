/** Controladores de respaldos .pnnc (todo rol admin). */
import type { Request, Response } from 'express';
import { createReadStream } from 'node:fs';
import { z } from 'zod';
import { logger } from '../../config/logger';
import {
  createBackup, listBackups, deleteBackup, verifyBackup,
  backupFilePath, backupExists, HttpBackupError,
} from './backups.service';

export async function getBackups(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ backups: await listBackups() });
  } catch (err) {
    logger.error({ err }, 'No se pudo listar respaldos');
    res.status(500).json({ error: 'No se pudieron listar los respaldos' });
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
    const ok = await deleteBackup(req.params.id);
    if (!ok) {
      res.status(404).json({ error: 'Respaldo no encontrado' });
      return;
    }
    res.json({ ok: true });
  } catch (err) {
    if (err instanceof HttpBackupError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'No se pudo eliminar el respaldo' });
  }
}

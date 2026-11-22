/**
 * Rutas de respaldos de la base de datos (.bbg). Todo requiere rol admin.
 *   GET    /api/backups              lista
 *   POST   /api/backups              crear respaldo manual
 *   GET    /api/backups/:id/download descargar el .bbg
 *   GET    /api/backups/:id/verify   verificar integridad (sha256)
 *   DELETE /api/backups/:id          eliminar
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import {
  getBackups, postBackup, downloadBackup, getBackupIntegrity, removeBackup, getPosture, restoreBackupCtrl,
} from './backups.controller';

export const backupsRouter = Router();
backupsRouter.use(authenticate, requireRole('admin'));

backupsRouter.get('/', getBackups);
backupsRouter.get('/posture', getPosture);
backupsRouter.post('/', postBackup);
backupsRouter.get('/:id/download', downloadBackup);
backupsRouter.get('/:id/verify', getBackupIntegrity);
backupsRouter.delete('/:id', removeBackup);
backupsRouter.post('/:id/restore', restoreBackupCtrl);

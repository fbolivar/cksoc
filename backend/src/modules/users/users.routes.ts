/**
 * Rutas de gestion de usuarios. Requieren autenticacion.
 * La administracion es solo para admin; el cambio de contrasena propia
 * lo puede hacer cualquier usuario autenticado.
 *
 *   GET    /api/users                      (admin)
 *   POST   /api/users                      (admin)
 *   PUT    /api/users/:id                  (admin)
 *   POST   /api/users/:id/reset-password   (admin)
 *   DELETE /api/users/:id                  (admin)
 *   POST   /api/users/me/change-password   (cualquier usuario)
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import {
  getUsers,
  postUser,
  putUser,
  resetPassword,
  deleteUser,
  changePassword,
} from './users.controller';

export const usersRouter = Router();
usersRouter.use(authenticate);

// Cambio de contrasena propia (cualquier rol)
usersRouter.post('/me/change-password', changePassword);

// Administracion (solo admin)
const onlyAdmin = requireRole('admin');
usersRouter.get('/', onlyAdmin, getUsers);
usersRouter.post('/', onlyAdmin, postUser);
usersRouter.put('/:id', onlyAdmin, putUser);
usersRouter.post('/:id/reset-password', onlyAdmin, resetPassword);
usersRouter.delete('/:id', onlyAdmin, deleteUser);

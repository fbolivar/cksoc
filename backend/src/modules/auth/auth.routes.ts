/**
 * Rutas del modulo de autenticacion.
 *   POST /api/auth/register  SOLO admin (crea cuentas; tambien via /api/users)
 *   POST /api/auth/login
 *   GET  /api/auth/me        (requiere token)
 */
import { Router } from 'express';
import { register, login, me } from './auth.controller';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { authLimiter } from '../../middleware/rateLimit';

export const authRouter = Router();

// El registro crea cuentas (incluido rol): solo un administrador autenticado
// puede hacerlo. Antes era publico y permitia auto-asignarse rol admin.
authRouter.post('/register', authenticate, requireRole('admin'), register);
authRouter.post('/login', authLimiter, login);
authRouter.get('/me', authenticate, me);

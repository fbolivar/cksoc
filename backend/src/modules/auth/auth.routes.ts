/**
 * Rutas del modulo de autenticacion.
 *   POST /api/auth/register  (publico en Fase 1; en Fase 5 se restringe a admin)
 *   POST /api/auth/login
 *   GET  /api/auth/me        (requiere token)
 */
import { Router } from 'express';
import { register, login, me } from './auth.controller';
import { authenticate } from '../../middleware/auth';
import { authLimiter } from '../../middleware/rateLimit';

export const authRouter = Router();

authRouter.post('/register', authLimiter, register);
authRouter.post('/login', authLimiter, login);
authRouter.get('/me', authenticate, me);

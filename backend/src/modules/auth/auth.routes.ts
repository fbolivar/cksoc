/**
 * Rutas del modulo de autenticacion.
 *   POST /api/auth/register      SOLO admin (crea cuentas; tambien via /api/users)
 *   POST /api/auth/login         paso 1 (credenciales)
 *   POST /api/auth/login/2fa     paso 2 (reto + codigo TOTP/respaldo)
 *   GET  /api/auth/me            (requiere token)
 *   GET  /api/auth/2fa/status    (requiere token) estado del 2FA propio
 *   POST /api/auth/2fa/setup     (requiere token) genera secreto + QR
 *   POST /api/auth/2fa/enable    (requiere token) confirma y activa + codigos respaldo
 *   POST /api/auth/2fa/disable   (requiere token) desactiva (password + codigo)
 */
import { Router } from 'express';
import {
  register, login, login2fa, me,
  twofaStatus, twofaSetup, twofaEnable, twofaDisable,
} from './auth.controller';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { authLimiter } from '../../middleware/rateLimit';

export const authRouter = Router();

// El registro crea cuentas (incluido rol): solo un administrador autenticado
// puede hacerlo. Antes era publico y permitia auto-asignarse rol admin.
authRouter.post('/register', authenticate, requireRole('admin'), register);
authRouter.post('/login', authLimiter, login);
authRouter.post('/login/2fa', authLimiter, login2fa);
authRouter.get('/me', authenticate, me);

// Gestion del 2FA de la propia cuenta (cualquier usuario autenticado).
authRouter.get('/2fa/status', authenticate, twofaStatus);
authRouter.post('/2fa/setup', authenticate, twofaSetup);
authRouter.post('/2fa/enable', authenticate, twofaEnable);
authRouter.post('/2fa/disable', authenticate, twofaDisable);

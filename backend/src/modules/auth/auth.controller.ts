/**
 * Controladores HTTP del modulo de autenticacion.
 * Valida entradas con zod y delega en el service.
 */
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  registerUser, loginUser, getProfile, HttpError,
  verifyChallenge, issueSessionForUser, revokeSessions,
} from './auth.service';
import { getStatus, setup, enable, disable, verifyCode } from './twofactor.service';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { auditFromReq } from '../audit/audit.service';

// El token de sesion tambien viaja en una cookie HttpOnly (no accesible por JS
// del navegador), lo que evita su robo por XSS. El backend acepta la cookie o el
// header Authorization (compatibilidad con sesiones previas). Same-origin +
// SameSite=strict mitiga CSRF.
const COOKIE_NAME = 'token';
function setSessionCookie(res: Response, token: string): void {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 8 * 60 * 60 * 1000, // 8h, acorde a JWT_EXPIRES_IN por defecto
  });
}
function clearSessionCookie(res: Response): void {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });
}

const credentialsSchema = z.object({
  email: z.string().email('Correo invalido'),
  password: z.string().min(8, 'La contrasena debe tener al menos 8 caracteres'),
});

const registerSchema = credentialsSchema.extend({
  fullName: z.string().min(2, 'Nombre invalido'),
  role: z.enum(['admin', 'analista', 'lector']).optional(),
});

export async function register(req: Request, res: Response): Promise<void> {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const { email, password, fullName, role } = parsed.data;
    const user = await registerUser(email, password, fullName, role);
    res.status(201).json({ user });
  } catch (err) {
    handleError(err, res);
  }
}

export async function login(req: Request, res: Response): Promise<void> {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const { email, password } = parsed.data;
    const result = await loginUser(email, password);
    if ('token' in result) setSessionCookie(res, result.token);
    void auditFromReq(req, {
      actorEmail: email, action: 'login', target: email, result: 'ok',
      detail: { twoFactor: 'twoFactor' in result },
    });
    res.json(result);
  } catch (err) {
    void auditFromReq(req, {
      actorEmail: parsed.data.email, action: 'login_failed', target: parsed.data.email, result: 'fail',
      detail: { reason: err instanceof HttpError ? err.message : 'error' },
    });
    handleError(err, res);
  }
}

export async function me(req: Request, res: Response): Promise<void> {
  try {
    const user = await getProfile(req.user!.id);
    res.json({ user });
  } catch (err) {
    handleError(err, res);
  }
}

const login2faSchema = z.object({
  challenge: z.string().min(10),
  code: z.string().min(6, 'Código inválido').max(20),
});

/** Segundo paso del login: canjea el reto + codigo 2FA por una sesion. */
export async function login2fa(req: Request, res: Response): Promise<void> {
  const parsed = login2faSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos' });
    return;
  }
  try {
    const userId = verifyChallenge(parsed.data.challenge);
    if (!(await verifyCode(userId, parsed.data.code))) {
      void auditFromReq(req, { actorId: userId, action: 'login_2fa_failed', result: 'fail' });
      res.status(401).json({ error: 'Código 2FA inválido' });
      return;
    }
    const session = await issueSessionForUser(userId);
    setSessionCookie(res, session.token);
    void auditFromReq(req, { actorId: userId, actorEmail: session.user?.email, action: 'login_2fa', result: 'ok' });
    res.json(session);
  } catch (err) {
    handleError(err, res);
  }
}

/** Cierra todas las sesiones del usuario y devuelve un token fresco para esta. */
export async function logoutAll(req: Request, res: Response): Promise<void> {
  try {
    const result = await revokeSessions(req.user!.id);
    if ('token' in result && typeof result.token === 'string') setSessionCookie(res, result.token);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'logout_all', result: 'ok' });
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
}

/** Cierra la sesion de este navegador: limpia la cookie HttpOnly. */
export function logout(_req: Request, res: Response): void {
  clearSessionCookie(res);
  res.json({ ok: true });
}

// --- Gestion de 2FA (usuario autenticado, para su propia cuenta) ---

export async function twofaStatus(req: Request, res: Response): Promise<void> {
  try {
    res.json(await getStatus(req.user!.id));
  } catch (err) {
    handleError(err, res);
  }
}

export async function twofaSetup(req: Request, res: Response): Promise<void> {
  try {
    res.json(await setup(req.user!.id, req.user!.email));
  } catch (err) {
    handleError(err, res);
  }
}

export async function twofaEnable(req: Request, res: Response): Promise<void> {
  const parsed = z.object({ code: z.string().min(6).max(10) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Código inválido' });
    return;
  }
  try {
    res.json(await enable(req.user!.id, parsed.data.code));
  } catch (err) {
    handleError(err, res);
  }
}

export async function twofaDisable(req: Request, res: Response): Promise<void> {
  const parsed = z.object({ password: z.string().min(1), code: z.string().min(6).max(20) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos' });
    return;
  }
  try {
    await disable(req.user!.id, parsed.data.password, parsed.data.code);
    res.json({ enabled: false });
  } catch (err) {
    handleError(err, res);
  }
}

function handleError(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  logger.error({ err }, 'Error en auth');
  res.status(500).json({ error: 'Error interno del servidor' });
}

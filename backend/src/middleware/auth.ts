/**
 * Middleware de autenticacion: valida el JWT del header Authorization.
 */
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { query } from '../config/db';
import { getCookie } from '../config/cookies';
import type { JwtPayload, AuthUser } from '../types';

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  // El token puede venir en la cookie HttpOnly (preferente, no accesible por JS)
  // o en el header Authorization (compatibilidad con sesiones/clientes previos).
  const header = req.headers.authorization;
  const token =
    (header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : null) ??
    getCookie(req.headers.cookie, 'token');
  if (!token) {
    res.status(401).json({ error: 'Token no proporcionado' });
    return;
  }
  let payload: JwtPayload;
  try {
    payload = jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }) as JwtPayload;
  } catch {
    res.status(401).json({ error: 'Token invalido o expirado' });
    return;
  }

  // Revocacion: el token solo vale si su version coincide con la del usuario y
  // la cuenta sigue activa. Cambiar la contrasena o "cerrar todas las sesiones"
  // incrementa token_version e invalida de inmediato los tokens anteriores.
  try {
    const rows = await query<{ token_version: number; is_active: boolean }>(
      'SELECT token_version, is_active FROM users WHERE id = $1',
      [payload.sub]
    );
    const u = rows[0];
    if (!u || !u.is_active || u.token_version !== payload.tv) {
      res.status(401).json({ error: 'Sesion expirada. Inicia sesion de nuevo.' });
      return;
    }
  } catch {
    res.status(500).json({ error: 'Error al validar la sesion' });
    return;
  }

  req.user = {
    id: payload.sub,
    email: payload.email,
    fullName: '', // se completa solo si se consulta el perfil
    role: payload.role,
  } satisfies AuthUser;
  next();
}

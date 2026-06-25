/**
 * Middleware de autenticacion: valida el JWT del header Authorization.
 */
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import type { JwtPayload, AuthUser } from '../types';

export function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Token no proporcionado' });
    return;
  }

  const token = header.slice('Bearer '.length);
  try {
    const payload = jwt.verify(token, env.JWT_SECRET) as JwtPayload;
    const user: AuthUser = {
      id: payload.sub,
      email: payload.email,
      fullName: '', // se completa solo si se consulta el perfil
      role: payload.role,
    };
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Token invalido o expirado' });
  }
}

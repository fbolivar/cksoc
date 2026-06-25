/**
 * Middleware de autorizacion por rol.
 * Uso: router.get('/x', authenticate, requireRole('admin'), handler)
 */
import type { Request, Response, NextFunction } from 'express';
import type { RoleName } from '../types';

export function requireRole(...allowed: RoleName[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'No autenticado' });
      return;
    }
    if (!allowed.includes(req.user.role)) {
      res.status(403).json({ error: 'No tienes permisos para esta accion' });
      return;
    }
    next();
  };
}

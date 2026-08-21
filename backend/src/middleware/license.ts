/**
 * Gate de licenciamiento: sin licencia válida y vigente, toda la API queda
 * bloqueada (402) salvo /api/auth (login) y /api/license (estado/activación),
 * para que un admin pueda entrar y cargar el código.
 */
import type { Request, Response, NextFunction } from 'express';
import { getLicenseStatus } from '../modules/license/license.service';

export async function licenseGate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const p = req.path || req.url;
  if (!p.startsWith('/api/')) { next(); return; }
  if (p.startsWith('/api/auth') || p.startsWith('/api/license') || p.startsWith('/api/health')) { next(); return; }
  try {
    const st = await getLicenseStatus();
    if (st.state === 'active') { next(); return; }
    res.status(402).json({ error: st.message, license: st.state, expiresAt: st.expiresAt ?? null });
  } catch {
    // Fallo al evaluar (p.ej. DB caída): no bloquear por un error transitorio.
    next();
  }
}

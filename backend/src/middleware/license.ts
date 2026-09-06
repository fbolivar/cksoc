/**
 * Gate de licenciamiento: sin licencia válida y vigente, toda la API queda
 * bloqueada (402) salvo /api/auth (login) y /api/license (estado/activación),
 * para que un admin pueda entrar y cargar el código.
 *
 * Periodo de gracia: una licencia recién vencida entra en estado 'grace' (7 días)
 * durante el cual el SOC sigue operando —con banner rojo de aviso— para no quedar
 * ciego por un trámite. Al agotarse la gracia pasa a 'expired' y el gate bloquea.
 */
import type { Request, Response, NextFunction } from 'express';
import { getLicenseStatus } from '../modules/license/license.service';

export async function licenseGate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const p = req.path || req.url;
  if (!p.startsWith('/api/')) { next(); return; }
  if (p.startsWith('/api/auth') || p.startsWith('/api/license') || p.startsWith('/api/health')) { next(); return; }
  try {
    const st = await getLicenseStatus();
    if (st.state === 'active' || st.state === 'grace') { next(); return; }
    res.status(402).json({ error: st.message, license: st.state, expiresAt: st.expiresAt ?? null });
  } catch {
    // Fallo al evaluar (p.ej. DB caída): no bloquear por un error transitorio.
    next();
  }
}

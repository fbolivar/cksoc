/**
 * Rate limiting para proteger el backend.
 * - apiLimiter: limite general para /api
 * - authLimiter: limite estricto para login/registro (anti fuerza bruta)
 */
import rateLimit from 'express-rate-limit';

export const apiLimiter = rateLimit({
  windowMs: 60_000, // 1 minuto
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas peticiones, intenta de nuevo en un momento' },
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60_000, // 15 minutos
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de autenticacion, espera unos minutos' },
});

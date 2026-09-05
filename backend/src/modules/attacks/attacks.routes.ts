/**
 * Rutas del mapa de ataques. Requieren autenticacion.
 *   GET /api/attacks/geo?hours=24
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getAttackGeo } from './attacks.service';
import { isGeoReady, geoError } from '../geo/geoip.service';
import { isThreatIntelConfigured } from '../threatintel/abuseipdb.service';
import { HttpError } from '../auth/auth.service';

export const attacksRouter = Router();
attacksRouter.use(authenticate);

// Destino de los arcos: Bogota, Colombia (sede PNNC)
export const PNNC_DESTINATION = { name: 'Bogotá, Colombia', lat: 4.711, lon: -74.0721 };

attacksRouter.get('/geo', async (req: Request, res: Response) => {
  if (!isGeoReady()) {
    res.status(503).json({ error: geoError() ?? 'Geolocalizacion no disponible' });
    return;
  }
  const h = Number(req.query.hours);
  const hours = Number.isFinite(h) && h > 0 && h <= 720 ? Math.floor(h) : 24;
  // Por defecto "Solo amenazas" (IOC/ataque/IPS/nivel alto/reputación mala); ?all=1 muestra todo el tráfico.
  const threatsOnly = !(req.query.all === '1' || req.query.all === 'true');
  try {
    const origins = await getAttackGeo(hours, threatsOnly);
    res.json({ hours, threatsOnly, destination: PNNC_DESTINATION, origins, threatIntel: isThreatIntelConfigured() });
  } catch (err) {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    // eslint-disable-next-line no-console
    console.error('Error en attacks/geo:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

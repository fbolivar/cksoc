/**
 * Precalentado de la cache del Resumen Ejecutivo.
 * getOverview() reconstruye agregaciones pesadas contra el Indexer (varios
 * segundos en frio). Como el TTL de su cache es corto, sin esto el primer
 * usuario que entra tras cada expiracion paga ese costo completo.
 * Aqui la refrescamos justo antes de que expire: la cache nunca queda fria y
 * el dato sigue siendo igual de reciente. Mismo criterio que
 * startMetricsBroadcast: una sola consulta compartida en vez de que cada
 * cliente machaque el Indexer.
 */
import { getOverview } from './overview.service';
import { logger } from '../../config/logger';

// Por debajo del TTL de la cache (30s) para renovarla antes de que caduque.
const INTERVAL_MS = 25_000;

export function startOverviewWarmup(): void {
  const warm = async (): Promise<void> => {
    const t0 = Date.now();
    try {
      // force: sin esto getOverview devolveria la cache vigente y no la renovaria.
      await getOverview({ force: true });
      logger.debug({ ms: Date.now() - t0 }, 'Cache de /overview precalentada');
    } catch (err) {
      // Un fallo puntual (Indexer ocupado) no debe tumbar el ciclo: se reintenta.
      logger.warn({ err }, 'Precalentado de /overview fallo; se reintenta en el proximo ciclo');
    }
  };

  void warm();
  setInterval(() => void warm(), INTERVAL_MS);
}

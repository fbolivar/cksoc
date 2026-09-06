/**
 * Precalentado de la cache del Command Center / Resumen Ejecutivo.
 * getOverview() y getPulse() reconstruyen agregaciones pesadas contra el Indexer
 * (varios segundos en frio). El Command Center dispara muchas de esas consultas
 * a la vez; si el primer usuario paga la reconstruccion bajo esa rafaga, el
 * Indexer se satura y algunas caen -> el panel mostraria "desconocido".
 * Aqui las refrescamos en segundo plano, a BAJA concurrencia (una tras otra),
 * justo antes de que expire su cache: el dato sigue reciente y la rafaga del
 * navegador lee cache caliente en vez de machacar el Indexer.
 */
import { getOverview } from './overview.service';
import { getPulse } from './pulse.service';
import { logger } from '../../config/logger';

// Por debajo del TTL de las caches (overview 60s, pulse 30s) para renovarlas
// antes de que caduquen.
const INTERVAL_MS = 25_000;

export function startOverviewWarmup(): void {
  const warm = async (): Promise<void> => {
    const t0 = Date.now();
    try {
      // Secuencial (no en paralelo) para no ser nosotros mismos la rafaga que
      // satura el Indexer. force: renueva pese a la cache vigente.
      await getOverview({ force: true });
      await getPulse({ force: true });
      logger.debug({ ms: Date.now() - t0 }, 'Caches de Command Center precalentadas');
    } catch (err) {
      // Un fallo puntual (Indexer ocupado) no debe tumbar el ciclo: se reintenta.
      logger.warn({ err }, 'Precalentado de Command Center fallo; se reintenta en el proximo ciclo');
    }
  };

  void warm();
  setInterval(() => void warm(), INTERVAL_MS);
}

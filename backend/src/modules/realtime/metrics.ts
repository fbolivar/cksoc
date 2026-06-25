/**
 * Difusion de metricas en tiempo real por Socket.io.
 * El backend consulta el Indexer periodicamente y emite un resumen
 * (total 24h + bandas de severidad) a todos los clientes conectados.
 * Evita que cada cliente machaque el Indexer: una sola consulta compartida.
 */
import type { Server as SocketServer } from 'socket.io';
import { getSummary } from '../wazuh/wazuh.service';

const INTERVAL_MS = 15_000;
const RANGE = '24h';

export interface LiveMetrics {
  total: number;
  byBand: { baja: number; media: number; alta: number; critica: number };
  updatedAt: string;
}

let lastMetrics: LiveMetrics | null = null;

export function startMetricsBroadcast(io: SocketServer): void {
  // Al conectarse un cliente, enviarle el ultimo valor conocido de inmediato.
  io.on('connection', (socket) => {
    if (lastMetrics) socket.emit('metrics:update', lastMetrics);
  });

  const tick = async (): Promise<void> => {
    // Solo consulta si hay alguien escuchando (ahorra llamadas al Indexer).
    if (io.engine.clientsCount === 0) return;
    try {
      const summary = await getSummary(RANGE);
      lastMetrics = {
        total: summary.total,
        byBand: summary.byBand,
        updatedAt: new Date().toISOString(),
      };
      io.emit('metrics:update', lastMetrics);
    } catch (err) {
      // No tumbar el intervalo por un fallo puntual del Indexer.
      const msg = err instanceof Error ? err.message : 'error';
      io.emit('metrics:error', { message: msg });
    }
  };

  setInterval(() => {
    void tick();
  }, INTERVAL_MS);
}

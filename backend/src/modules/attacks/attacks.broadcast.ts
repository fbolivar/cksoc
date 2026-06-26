/**
 * Emite por WebSocket un evento "new_attack" cuando llega una alerta nueva
 * con IP publica geolocalizable. El mapa del frontend lo usa para animar
 * un arco/punto en vivo.
 */
import type { Server as SocketServer } from 'socket.io';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { geolocate, extractPublicIp, isGeoReady } from '../geo/geoip.service';

const POLL_MS = 20_000;

export interface NewAttack {
  ip: string;
  country: string;
  city: string;
  isoCode: string;
  lat: number;
  lon: number;
  severity: number;
  description: string;
  ts: string;
}

let lastTs: string | null = null;

export function startAttacksBroadcast(io: SocketServer): void {
  if (!isGeoReady()) return;

  const tick = async (): Promise<void> => {
    if (io.engine.clientsCount === 0) return;
    const client = getIndexerClient();
    const gte = lastTs ?? 'now-2m';
    try {
      const { data } = await client.post<{
        hits: {
          hits: {
            _source: {
              timestamp: string;
              rule?: { level?: number; description?: string };
              data?: { srcip?: string; remip?: string };
            };
          }[];
        };
      }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
        size: 30,
        sort: [{ timestamp: 'asc' }],
        _source: ['timestamp', 'rule.level', 'rule.description', 'data.srcip', 'data.remip'],
        query: {
          bool: {
            filter: [{ range: { timestamp: { gt: gte } } }],
            should: [{ exists: { field: 'data.srcip' } }, { exists: { field: 'data.remip' } }],
            minimum_should_match: 1,
          },
        },
      });

      for (const h of data.hits.hits) {
        const s = h._source;
        lastTs = s.timestamp; // avanza el cursor
        const ip = extractPublicIp(s.data ?? {});
        if (!ip) continue;
        const geo = geolocate(ip);
        if (!geo) continue;
        const attack: NewAttack = {
          ip,
          country: geo.country,
          city: geo.city,
          isoCode: geo.isoCode,
          lat: geo.lat,
          lon: geo.lon,
          severity: s.rule?.level ?? 0,
          description: s.rule?.description ?? '',
          ts: s.timestamp,
        };
        io.emit('new_attack', attack);
      }
    } catch {
      // Silencioso: un fallo puntual del Indexer no debe frenar el poll.
    }
  };

  setInterval(() => void tick(), POLL_MS);
  // eslint-disable-next-line no-console
  console.log('🛰️  Emisor de ataques en vivo activo');
}

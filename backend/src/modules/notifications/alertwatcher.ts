/**
 * Vigilante de alertas: consulta el Indexer periodicamente y dispara correos
 * INMEDIATOS para lo que requiere accion, respetando anti-flood y tope diario.
 *
 * Criterio inmediato:
 *   - nivel >= NOTIFY_IMMEDIATE_MIN_LEVEL (12), o
 *   - rule.id en NOTIFY_BRUTEFORCE_RULES (100031,100036), o
 *   - IP origen publica con reputacion AbuseIPDB >= NOTIFY_ABUSE_MIN_SCORE.
 * Nunca inmediato por nivel < NOTIFY_DIGEST_MIN_LEVEL (7).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { geolocate, extractPublicIp } from '../geo/geoip.service';
import { checkReputation } from '../threatintel/abuseipdb.service';
import {
  getSettings,
  recentlyNotified,
  sendCapped,
  immediateEmail,
  type ImmediateAlert,
} from './notify.engine';
import { runPlaybooksForAlert } from '../playbooks/playbooks.service';

const BRUTE = new Set(env.NOTIFY_BRUTEFORCE_RULES.split(',').map((s) => s.trim()).filter(Boolean));
let lastTs: string | null = null;

interface Hit {
  _id: string;
  _source: {
    timestamp: string;
    rule?: { id?: string; level?: number; description?: string; mitre?: { id?: string[] }; groups?: string[] };
    agent?: { name?: string };
    data?: { srcip?: string; remip?: string };
  };
}

export function startAlertWatcher(): void {
  const tick = async (): Promise<void> => {
    let settings;
    try {
      settings = await getSettings();
    } catch {
      return; // BD no disponible
    }
    if (!settings.immediateEnabled || settings.recipients.length === 0) return;

    const client = getIndexerClient();
    const gte = lastTs ?? 'now-5m';
    let hits: Hit[];
    try {
      const { data } = await client.post<{ hits: { hits: Hit[] } }>(
        `/${env.WAZUH_ALERTS_INDEX}/_search`,
        {
          size: 50,
          sort: [{ timestamp: 'asc' }],
          _source: ['timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.mitre.id', 'rule.groups', 'agent.name', 'data.srcip', 'data.remip'],
          query: {
            bool: {
              filter: [{ range: { timestamp: { gt: gte } } }],
              should: [
                { range: { 'rule.level': { gte: env.NOTIFY_IMMEDIATE_MIN_LEVEL } } },
                { terms: { 'rule.id': [...BRUTE] } },
                {
                  bool: {
                    filter: [{ range: { 'rule.level': { gte: env.NOTIFY_DIGEST_MIN_LEVEL } } }],
                    should: [{ exists: { field: 'data.srcip' } }, { exists: { field: 'data.remip' } }],
                    minimum_should_match: 1,
                  },
                },
              ],
              minimum_should_match: 1,
            },
          },
        }
      );
      hits = data.hits.hits;
    } catch {
      return; // fallo puntual del Indexer
    }

    for (const h of hits) {
      const s = h._source;
      lastTs = s.timestamp; // avanza el cursor siempre
      const level = s.rule?.level ?? 0;
      const ruleId = s.rule?.id ?? '';
      const ip = extractPublicIp(s.data ?? {});

      // SOAR: evaluar la alerta contra los playbooks habilitados (best-effort,
      // no bloquea la notificacion). El motor respeta modo/cooldown/lista blanca.
      void runPlaybooksForAlert({
        alertId: h._id, level, ruleId,
        description: s.rule?.description ?? '',
        agent: s.agent?.name ?? '—',
        ip: ip ?? null,
        mitre: s.rule?.mitre?.id ?? [],
        groups: s.rule?.groups ?? [],
        timestamp: s.timestamp,
      });

      // Decidir si es inmediato
      let immediate = level >= env.NOTIFY_IMMEDIATE_MIN_LEVEL || BRUTE.has(ruleId);
      let reputation = null as { abuseScore: number; totalReports: number } | null;
      if (!immediate && ip && level >= env.NOTIFY_DIGEST_MIN_LEVEL) {
        const rep = await checkReputation(ip);
        reputation = { abuseScore: rep.abuseScore, totalReports: rep.totalReports };
        if (rep.abuseScore >= env.NOTIFY_ABUSE_MIN_SCORE) immediate = true;
      }
      if (!immediate) continue; // a digest, no correo ahora

      const origen = ip ?? s.agent?.name ?? 'desconocido';
      if (await recentlyNotified(ruleId, origen)) continue; // anti-flood

      // Enriquecer
      const geo = ip ? geolocate(ip) : null;
      if (ip && !reputation) {
        const rep = await checkReputation(ip);
        reputation = { abuseScore: rep.abuseScore, totalReports: rep.totalReports };
      }
      const alert: ImmediateAlert = {
        level, ruleId,
        description: s.rule?.description ?? '',
        agent: s.agent?.name ?? '—',
        origin: ip ?? undefined,
        geo: geo ? { country: geo.country, city: geo.city } : null,
        reputation,
        timestamp: s.timestamp,
      };
      const { subject, html, text } = immediateEmail(alert);
      await sendCapped(settings.recipients, subject, html, text, {
        tipo: 'immediate', ruleId, ruleName: alert.description, origen,
      });
    }
  };

  setInterval(() => void tick(), env.NOTIFY_POLL_SECONDS * 1000);
  // eslint-disable-next-line no-console
  console.log(`📧 Vigilante de alertas inmediatas activo (cada ${env.NOTIFY_POLL_SECONDS}s)`);
}

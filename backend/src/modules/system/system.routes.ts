/**
 * Estado del sistema (Fase 5): conexiones y configuracion operativa.
 *   GET /api/system/status  (autenticado)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { env } from '../../config/env';
import { countAlerts } from '../wazuh/wazuh.service';
import { getAgentsSummary } from '../wazuh/agents.service';
import { channelStatus } from '../notifications/notify.service';
import { pingDb } from '../../config/db';

export const systemRouter = Router();
systemRouter.use(authenticate);

systemRouter.get('/status', async (_req: Request, res: Response) => {
  const [db, indexer, wazuhApi] = await Promise.all([
    pingDb(),
    countAlerts('1m').then(() => true).catch(() => false),
    getAgentsSummary().then(() => true).catch(() => false),
  ]);

  res.json({
    database: db,
    indexer: { url: env.WAZUH_INDEXER_URL ?? null, reachable: indexer },
    wazuhApi: { url: env.WAZUH_API_URL ?? null, reachable: wazuhApi },
    channels: channelStatus(),
    scheduler: {
      notifications: { active: true, interval: '1 min' },
      reports: {
        enabled: env.REPORT_SCHEDULE_ENABLED,
        cron: env.REPORT_SCHEDULE_CRON,
        range: env.REPORT_SCHEDULE_RANGE,
      },
    },
    environment: env.NODE_ENV,
  });
});

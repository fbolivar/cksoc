/** Estado del sistema. */
import { api } from './api';

export interface SystemStatus {
  database: boolean;
  indexer: { url: string | null; reachable: boolean };
  wazuhApi: { url: string | null; reachable: boolean };
  channels: { email: { configured: boolean }; telegram: { configured: boolean } };
  scheduler: {
    notifications: { active: boolean; interval: string };
    reports: { enabled: boolean; cron: string; range: string };
  };
  environment: string;
}

export const systemApi = {
  status: () => api.get<SystemStatus>('/system/status').then((r) => r.data),
};

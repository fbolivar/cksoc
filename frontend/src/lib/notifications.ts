/** Tipos y llamadas a la API de notificaciones. */
import { api } from './api';

export type Channel = 'email' | 'telegram';

export interface AlertRule {
  id: string;
  name: string;
  description: string | null;
  minLevel: number;
  ruleGroups: string[];
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  channels: Channel[];
  emailRecipients: string[];
  telegramChatIds: string[];
  enabled: boolean;
  lastCheckedAt: string | null;
  lastTriggeredAt: string | null;
  createdAt: string;
}

export interface RuleInput {
  name: string;
  description?: string;
  minLevel: number;
  ruleGroups: string[];
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  channels: Channel[];
  emailRecipients: string[];
  telegramChatIds: string[];
  enabled: boolean;
}

export interface ChannelStatus {
  email: { configured: boolean };
  telegram: { configured: boolean };
}

export interface LogEntry {
  id: string;
  rule_name: string | null;
  channel: string;
  recipients: string[];
  matched_count: number | null;
  status: 'sent' | 'failed';
  error: string | null;
  created_at: string;
}

export interface NotifySettings {
  recipients: string[];
  immediateEnabled: boolean;
  digestEnabled: boolean;
  digestHour: number;
}

export interface DailyStatus {
  sent: number;
  cap: number;
  capReached: boolean;
}

export const notificationsApi = {
  getSettings: () =>
    api
      .get<{ settings: NotifySettings; daily: DailyStatus; channels: ChannelStatus }>('/notifications/settings')
      .then((r) => r.data),
  updateSettings: (s: Partial<NotifySettings>) =>
    api.put<{ settings: NotifySettings }>('/notifications/settings', s).then((r) => r.data.settings),
  sendDigest: () => api.post('/notifications/digest/send').then((r) => r.data),
  testImmediate: () => api.post('/notifications/test-immediate').then((r) => r.data),

  list: () =>
    api
      .get<{ rules: AlertRule[]; channels: ChannelStatus }>('/notifications/rules')
      .then((r) => r.data),
  create: (input: RuleInput) =>
    api.post<{ rule: AlertRule }>('/notifications/rules', input).then((r) => r.data.rule),
  update: (id: string, input: RuleInput) =>
    api.put<{ rule: AlertRule }>(`/notifications/rules/${id}`, input).then((r) => r.data.rule),
  remove: (id: string) => api.delete(`/notifications/rules/${id}`).then((r) => r.data),
  test: (channel: Channel, target: string) =>
    api.post('/notifications/test', { channel, target }).then((r) => r.data),
  checkChannel: (channel: Channel) =>
    api.get(`/notifications/channels/${channel}/check`).then((r) => r.data),
  evaluateNow: () => api.post('/notifications/evaluate').then((r) => r.data),
  log: () => api.get<{ log: LogEntry[] }>('/notifications/log').then((r) => r.data.log),
};

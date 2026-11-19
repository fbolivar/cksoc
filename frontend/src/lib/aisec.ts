/** API del módulo Seguridad de IA (inventario + monitoreo de M365 Copilot). */
import { api } from './api';

export interface NetAiRow { service: string; name: string; vendor: string; devices: number; hits: number; lastSeen: string; sanctioned: boolean }
export interface AiInventory {
  range: string;
  kpis: { aiServices: number; shadowServices: number; networkDevices: number; copilotInteractions: number; copilotUsers: number; jailbreakAttempts: number };
  network: NetAiRow[];
  copilot: { interactions: number; users: number; jailbreakAttempts: number; lastSeen: string; byApp: { key: string; count: number }[] };
}

export interface CopilotRow { time: string; user: string; app: string; clientIp: string | null; jailbreak: boolean; contexts: string[] }
export interface CopilotSummary {
  range: string;
  interactions: number;
  users: number;
  jailbreakAttempts: number;
  offHours: number;
  byApp: { key: string; count: number }[];
  topUsers: { key: string; count: number }[];
  topResources: { resource: string; hits: number }[];
  jailbreakList: CopilotRow[];
  recent: CopilotRow[];
}

export const aisecApi = {
  inventory: (range = '7d') => api.get<AiInventory>('/aisec/inventory', { params: { range } }).then((r) => r.data),
  copilot: (range = '7d') => api.get<CopilotSummary>('/aisec/copilot', { params: { range } }).then((r) => r.data),
};

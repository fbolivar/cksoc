/** API del módulo Seguridad de IA (inventario + Copilot + exfiltración + riesgo + postura). */
import { api } from './api';

export interface NetAiRow { service: string; name: string; vendor: string; devices: number; hits: number; lastSeen: string; sanctioned: boolean }
export interface AiInventory {
  range: string;
  kpis: { aiServices: number; shadowServices: number; networkDevices: number; copilotInteractions: number; copilotUsers: number; jailbreakAttempts: number };
  network: NetAiRow[];
  copilot: { interactions: number; users: number; jailbreakAttempts: number; sanctioned: boolean; lastSeen: string; byApp: { key: string; count: number }[] };
}
export interface CopilotRow { time: string; user: string; app: string; agent: string | null; clientIp: string | null; jailbreak: boolean; xpia: boolean; contexts: string[] }
export interface AiAgent { id: string; label: string; interactions: number; builtin: boolean }
export interface CitationRow { url: string; type: string; hits: number }
export interface CopilotSummary {
  range: string; interactions: number; users: number; jailbreakAttempts: number; xpiaAttempts: number; offHours: number; sanctioned: boolean;
  byApp: { key: string; count: number }[]; topUsers: { key: string; count: number }[];
  topResources: { resource: string; hits: number }[]; agents: AiAgent[]; externalCitations: number; topCitations: CitationRow[];
  jailbreakList: CopilotRow[]; xpiaList: CopilotRow[]; recent: CopilotRow[];
}
export interface ExfilRow { srcip: string; host: string | null; service: string; name: string; sentMB: number; rcvdMB: number; hits: number; lastSeen: string; sanctioned: boolean; flagged: boolean }
export interface ExfilSummary { range: string; thresholdMB: number; totalSentMB: number; flagged: number; rows: ExfilRow[] }
export interface RiskEntity { id: string; kind: 'user' | 'device'; label: string; score: number; reasons: string[] }
export interface RiskNode { id: string; type: 'user' | 'device' | 'service' | 'resource'; label: string; risk: number }
export interface RiskEdge { from: string; to: string; weight: number; shadow?: boolean }
export interface AiRisk { range: string; entities: RiskEntity[]; graph: { nodes: RiskNode[]; edges: RiskEdge[] } }
export interface PostureItem { id: string; category: string; owasp: string; status: 'ok' | 'warn' | 'critical'; severity: number; evidence: number; finding: string; recommendation: string }
export interface AiPosture { range: string; score: number; items: PostureItem[] }
export interface AiOverview { range: string; inventory: AiInventory; copilot: CopilotSummary; exfil: ExfilSummary; risk: AiRisk; posture: AiPosture }

export const aisecApi = {
  overview: (range = '7d') => api.get<AiOverview>('/aisec/overview', { params: { range } }).then((r) => r.data),
  inventory: (range = '7d') => api.get<AiInventory>('/aisec/inventory', { params: { range } }).then((r) => r.data),
  copilot: (range = '7d') => api.get<CopilotSummary>('/aisec/copilot', { params: { range } }).then((r) => r.data),
};

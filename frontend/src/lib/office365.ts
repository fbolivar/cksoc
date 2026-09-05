/** Cliente del dashboard Office 365. */
import { api } from './api';

export interface NamedCount { key: string; count: number; country?: string; system?: boolean }
export interface RuleCount { desc: string; count: number; level: number }
export interface TimePoint { ts: number; count: number }

export interface O365RiskDetail { label: string; count: number }
export interface O365Risk {
  key: string;
  label: string;
  severity: 'critica' | 'alta' | 'media';
  hint: string;
  count: number;
  detail: O365RiskDetail[];
  active: boolean;
}
export interface O365Risks { clean: boolean; items: O365Risk[] }

export interface O365Overview {
  risks: O365Risks;
  range: string;
  total: number;
  users: number;
  clientIps: number;
  signIns: number;
  signInsFailed: number;
  downloads: number;
  timeline: TimePoint[];
  topUsers: NamedCount[];
  topClientIps: NamedCount[];
  topOperations: NamedCount[];
  workloads: NamedCount[];
  topRules: RuleCount[];
  signInUsers: NamedCount[];
  signInIps: NamedCount[];
  fileTopUsers: NamedCount[];
  generatedAt: string;
}

export interface M365Identity { displayName: string; upn: string; enabled: boolean; guest: boolean; created: string | null }
export interface M365Directory {
  configured: boolean;
  total: number; enabled: number; disabled: number; guests: number;
  truncated: boolean;
  recent: M365Identity[];
  disabledList: M365Identity[];
  guestList: M365Identity[];
  generatedAt: string;
}

export type RecSeverity = 'alta' | 'media' | 'baja';
export interface IdentityRec {
  kind: 'guest' | 'signin';
  upn: string; displayName: string; mail: string; enabled: boolean;
  severity: RecSeverity; title: string; reason: string;
  meta: { label: string; value: string }[];
  actions: string[];
}
export interface IdentityRecs { configured: boolean; generatedAt: string; items: IdentityRec[] }

export const office365Api = {
  overview: (range: string) => api.get<O365Overview>('/office365', { params: { range } }).then((r) => r.data),
  identities: () => api.get<M365Directory>('/office365/identities').then((r) => r.data),
  recommendations: () => api.get<IdentityRecs>('/office365/recommendations').then((r) => r.data),
  disableIdentity: (upn: string) => api.post('/office365/identities/disable', { upn }).then((r) => r.data),
  deleteIdentity: (upn: string) => api.post('/office365/identities/delete', { upn }).then((r) => r.data),
};

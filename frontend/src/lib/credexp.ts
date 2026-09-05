/** API del monitoreo de exposición de credenciales (HIBP Domain). */
import { api } from './api';

export interface CredDomain {
  domain: string;
  habilitado: boolean;
  verificado: boolean;
  ultimo_scan: string | null;
  ultimo_error: string | null;
  expuestas?: number;
}
export interface CredAccount {
  id: string;
  domain: string;
  alias: string;
  brechas: string[];
  num_brechas: number;
  estado: 'open' | 'ack' | 'dismissed';
  primera_vez: string;
  ultima_vez: string;
}
export interface CredSummary {
  configurado: boolean;
  dominios: CredDomain[];
  totalExpuestas: number;
  abiertas: number;
  cuentasCriticas: number;
  topBrechas: { name: string; title: string | null; cuentas: number }[];
  ultimoScan: string | null;
}

export interface HibpDiagnostics {
  keyConfigured: boolean;
  keyValid: boolean | null;
  plan: { name: string; description: string; subscribedUntil: string; maxBreachedPerDomain: number; rpm: number } | null;
  hibpDomains: { domain: string; pwnCount: number }[];
  monitored: { domain: string; registeredInHibp: boolean; verificado: boolean; ultimoScan: string | null; ultimoError: string | null; expuestas: number }[];
  ready: boolean;
  steps: { step: string; detail: string }[];
  checkedAt: string;
}

export const credExpApi = {
  summary: () => api.get<CredSummary>('/credential-exposure/summary').then((r) => r.data),
  diagnostics: () => api.get<HibpDiagnostics>('/credential-exposure/diagnostics').then((r) => r.data),
  accounts: (f: { domain?: string; estado?: string; q?: string } = {}) =>
    api.get<{ accounts: CredAccount[] }>('/credential-exposure/accounts', { params: f }).then((r) => r.data.accounts),
  addDomain: (domain: string) =>
    api.post<{ domain: CredDomain }>('/credential-exposure/domains', { domain }).then((r) => r.data.domain),
  removeDomain: (domain: string) =>
    api.delete(`/credential-exposure/domains/${encodeURIComponent(domain)}`).then((r) => r.data),
  scanAll: () =>
    api.post<{ resultados: { domain: string; total: number; nuevas: number; error?: string }[] }>('/credential-exposure/scan').then((r) => r.data.resultados),
  scanDomain: (domain: string) =>
    api.post<{ total: number; nuevas: number }>(`/credential-exposure/scan/${encodeURIComponent(domain)}`).then((r) => r.data),
  setStatus: (id: string, estado: 'open' | 'ack' | 'dismissed') =>
    api.put(`/credential-exposure/accounts/${id}/status`, { estado }).then((r) => r.data),
};

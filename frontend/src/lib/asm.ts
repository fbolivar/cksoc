/** API del módulo ASM (Attack Surface Management externo). */
import { api } from './api';

export type Sev = 'critica' | 'alta' | 'media' | 'baja' | 'info';

export interface AsmDomain {
  domain: string;
  habilitado: boolean;
  ultimo_scan: string | null;
  ultimo_error: string | null;
  activos: number;
  hallazgos: number;
}
export interface AsmAsset {
  domain: string;
  host: string;
  ip: string | null;
  fuente: string;
  activo: boolean;
  primera_vez: string;
  ultima_vez: string;
}
export interface AsmFinding {
  id: string;
  domain: string;
  host: string;
  ip: string | null;
  tipo: string;
  puerto: number;
  severidad: Sev;
  detalle: string;
  estado: string;
  primera_vez: string;
  ultima_vez: string;
}
export interface AsmOverview {
  dominios: number;
  hosts: number;
  ips: number;
  hallazgos: Record<Sev, number>;
  top: AsmFinding[];
}
export interface AsmScanResult {
  domain: string;
  hosts: number;
  assets: number;
  openPorts: number;
  nuevos: number;
}

export const asmApi = {
  overview: () => api.get<AsmOverview>('/asm/overview').then((r) => r.data),
  domains: () => api.get<{ domains: AsmDomain[] }>('/asm/domains').then((r) => r.data.domains),
  assets: (domain?: string) =>
    api.get<{ assets: AsmAsset[] }>('/asm/assets', { params: domain ? { domain } : {} }).then((r) => r.data.assets),
  findings: (f: { estado?: string; severidad?: string } = {}) =>
    api.get<{ findings: AsmFinding[] }>('/asm/findings', { params: f }).then((r) => r.data.findings),
  addDomain: (domain: string) =>
    api.post<{ domain: { domain: string } }>('/asm/domains', { domain }).then((r) => r.data.domain),
  removeDomain: (domain: string) =>
    api.delete(`/asm/domains/${encodeURIComponent(domain)}`).then((r) => r.data),
  scanAll: () =>
    api.post<{ resultados: AsmScanResult[] }>('/asm/scan').then((r) => r.data.resultados),
  scanDomain: (domain: string) =>
    api.post<AsmScanResult>(`/asm/scan/${encodeURIComponent(domain)}`).then((r) => r.data),
  setFindingStatus: (id: string, estado: 'open' | 'resolved' | 'dismissed') =>
    api.put(`/asm/findings/${id}/status`, { estado }).then((r) => r.data),
};

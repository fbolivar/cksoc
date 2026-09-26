/** API del módulo Shadow-AI (uso de IA generativa detectado por red). */
import { api } from './api';

export interface AiServiceRow {
  service: string; name: string; vendor: string; sanctioned: boolean;
  hits: number; devices: number; last_seen: string;
}
export interface AiDevice {
  srcip: string; host: string | null; srcuser: string | null;
  servicios: number; hits: number; shadow: boolean; last_seen: string;
}
export interface AiKpis {
  dispositivos: number; servicios: number; shadowDispositivos: number; shadowServicios: number; shadowHits: number;
}
export interface AiOverview { kpis: AiKpis; services: AiServiceRow[]; devices: AiDevice[]; lastScan: string | null }
export interface AiCatalog { id: string; name: string; vendor: string; sanctioned: boolean }
export interface AiScanResult { window: string; devices: number; services: number; nuevos: number; nuevosShadow: { srcip: string; host: string | null; service: string }[] }

export const shadowAiApi = {
  overview: () => api.get<AiOverview>('/shadow-ai/overview').then((r) => r.data),
  usage: (shadow?: boolean) =>
    api.get('/shadow-ai/usage', { params: shadow ? { shadow: 1 } : {} }).then((r) => r.data.usage),
  services: () => api.get<{ services: AiCatalog[] }>('/shadow-ai/services').then((r) => r.data.services),
  scan: (range = '7d') => api.post<AiScanResult>('/shadow-ai/scan', { range }).then((r) => r.data),
  setPolicy: (service: string, sanctioned: boolean) =>
    api.put(`/shadow-ai/policy/${encodeURIComponent(service)}`, { sanctioned }).then((r) => r.data),
  forget: (srcip: string, service: string) =>
    api.delete(`/shadow-ai/usage/${encodeURIComponent(srcip)}/${encodeURIComponent(service)}`).then((r) => r.data),
};

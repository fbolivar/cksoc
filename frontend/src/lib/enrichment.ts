/** Cliente de enriquecimiento de IPs (geo + reputación + IOC + actividad). */
import { api } from './api';

export type Verdict = 'malicioso' | 'sospechoso' | 'limpio' | 'interno' | 'desconocido';

export interface IpEnrichment {
  ip: string;
  isPublic: boolean;
  verdict: Verdict;
  geo: { country: string; city: string; isoCode: string } | null;
  reputation: { abuseScore: number; totalReports: number; isp: string | null; usageType: string | null; domain: string | null; lastReportedAt: string | null; configured: boolean } | null;
  ioc: { matched: boolean; source?: string; description?: string } | null;
  alerts24h: number;
  generatedAt: string;
}

export const enrichmentApi = {
  ip: (ip: string) => api.get<IpEnrichment>(`/enrichment/ip/${encodeURIComponent(ip)}`).then((r) => r.data),
};

export const VERDICT_META: Record<Verdict, { label: string; var: string }> = {
  malicioso: { label: 'Malicioso', var: 'destructive' },
  sospechoso: { label: 'Sospechoso', var: 'warn-orange' },
  limpio: { label: 'Limpio', var: 'success' },
  interno: { label: 'Interno', var: 'cyan' },
  desconocido: { label: 'Desconocido', var: 'muted-foreground' },
};

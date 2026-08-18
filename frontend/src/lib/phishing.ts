/** Cliente de factor humano / campañas de phishing. */
import { api } from './api';

export interface Campaign {
  id: string;
  name: string;
  run_date: string;
  sent: number;
  clicked: number;
  reported: number;
  trained_pct: number;
  note: string | null;
  created_at: string;
}

export interface HumanFactor {
  clickRate: number;
  reportRate: number;
  trainedPct: number;
  posture: number;
  totalSent: number;
  campaigns: number;
  lastRun: string | null;
}

export const phishingApi = {
  get: () => api.get<{ campaigns: Campaign[]; metrics: HumanFactor | null }>('/phishing').then((r) => r.data),
  create: (input: { name: string; runDate: string; sent: number; clicked: number; reported: number; trainedPct: number; note?: string }) =>
    api.post<Campaign>('/phishing', input).then((r) => r.data),
  remove: (id: string) => api.delete(`/phishing/${id}`).then((r) => r.data),
};

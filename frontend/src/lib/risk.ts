/** Cliente del Tablero Ejecutivo de Riesgo. */
import { api } from './api';

export type Status = 'good' | 'warn' | 'bad' | 'pending';

export interface Kpi { label: string; value: string; status: Status; source: 'real' | 'pending'; note?: string }
export interface Domain {
  key: string; title: string; businessQuestion: string; status: Status; posture: number | null; kpis: Kpi[];
}
export interface RiskBoard {
  generatedAt: string;
  index: { score: number; level: 'bajo' | 'medio' | 'alto' | 'critico'; label: string; measuredDomains: number };
  overallQuestion: string;
  domains: Domain[];
}

export const riskApi = {
  board: () => api.get<RiskBoard>('/risk/board').then((r) => r.data),
};

export const STATUS_COLOR: Record<Status, string> = {
  good: 'text-primary',
  warn: 'text-warn',
  bad: 'text-destructive-foreground',
  pending: 'text-muted-foreground/50',
};
export const STATUS_DOT: Record<Status, string> = {
  good: 'bg-primary',
  warn: 'bg-warn',
  bad: 'bg-destructive',
  pending: 'bg-muted-foreground/30',
};
export const LEVEL_COLOR: Record<string, string> = {
  bajo: 'text-primary',
  medio: 'text-warn',
  alto: 'text-orange-400',
  critico: 'text-destructive-foreground',
};

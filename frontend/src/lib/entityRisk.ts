/** Cliente del Risk-Based Alerting (riesgo acumulado por entidad). */
import { api } from './api';

export type RiskBand = 'critico' | 'alto' | 'medio' | 'bajo';

export interface RiskContribution { source: string; label: string; points: number }
export interface EntityRisk {
  entity: string;
  type: 'host' | 'user';
  score: number;
  band: RiskBand;
  contributions: RiskContribution[];
  alerts: number;
  critAlerts: number;
  extra?: Record<string, string | number>;
}
export interface EntityRiskReport {
  range: string;
  hosts: EntityRisk[];
  users: EntityRisk[];
  generatedAt: string;
}

export const entityRiskApi = {
  get: (range: string) => api.get<EntityRiskReport>('/entity-risk', { params: { range } }).then((r) => r.data),
  triage: (limit = 6) => api.get<{ items: EntityRisk[] }>('/entity-risk/triage', { params: { limit } }).then((r) => r.data.items),
};

/** Color (token CSS) por banda de riesgo. */
export const BAND_VAR: Record<RiskBand, string> = {
  critico: 'destructive',
  alto: 'warn-orange',
  medio: 'primary',
  bajo: 'success',
};
export const BAND_LABEL: Record<RiskBand, string> = {
  critico: 'Crítico', alto: 'Alto', medio: 'Medio', bajo: 'Bajo',
};

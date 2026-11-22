/** API del Scorecard de Exposición Externa. */
import { api } from './api';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export interface ScoreCategory { key: string; label: string; score: number | null; grade: Grade | null; weight: number; resumen: string; hallazgos: string[] }
export interface ScorecardData { generatedAt: string; score: number; grade: Grade; categorias: ScoreCategory[]; resumenEjecutivo: string }

export const scorecardApi = {
  get: () => api.get<ScorecardData>('/scorecard').then((r) => r.data),
  refresh: () => api.post<ScorecardData>('/scorecard/refresh', {}, { timeout: 60_000 }).then((r) => r.data),
};

export function gradeColor(g: Grade | null): string {
  return g === 'A' ? '#10b981' : g === 'B' ? '#84cc16' : g === 'C' ? '#eab308' : g === 'D' ? '#f97316' : g === 'F' ? '#ef4444' : '#64748b';
}

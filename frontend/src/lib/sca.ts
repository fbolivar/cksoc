/** Tipos y API de Configuration Assessment (SCA). */
import { api } from './api';

export interface ScaPolicy {
  agentId: string;
  agent: string;
  os: string;
  policyId: string;
  policy: string;
  score: number;
  pass: number;
  fail: number;
  total: number;
  endScan: string | null;
}

export type ScaImpact = 'alto' | 'medio' | 'contextual';

export interface FailedCheck {
  title: string;
  count: number;
  remediation: string;
  rationale: string;
  impact: ScaImpact;
}

export interface ScaData {
  resumen: {
    agentesEvaluados: number;
    agentesActivos: number;
    activosSinSca: string[];
    scorePromedio: number;
    totalChecks: number;
    pass: number;
    fail: number;
    failAlto: number;
  };
  agentes: ScaPolicy[];
  topFallidos: FailedCheck[];
}

export const IMPACT_META: Record<ScaImpact, { label: string; color: string }> = {
  alto: { label: 'Alto impacto', color: '#ef4444' },
  medio: { label: 'Medio', color: '#f97316' },
  contextual: { label: 'Contextual', color: '#94a3b8' },
};

export const scaApi = {
  get: () => api.get<ScaData>('/sca').then((r) => r.data),
};

/** Color segun score de cumplimiento (rojo bajo -> verde alto). */
export function scoreColor(score: number): string {
  if (score >= 80) return '#22c55e';
  if (score >= 50) return '#eab308';
  if (score >= 30) return '#f97316';
  return '#ef4444';
}

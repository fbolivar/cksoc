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

export interface FailedCheck {
  title: string;
  count: number;
  remediation: string;
  rationale: string;
}

export interface ScaData {
  resumen: { agentesEvaluados: number; scorePromedio: number; totalChecks: number; pass: number; fail: number };
  agentes: ScaPolicy[];
  topFallidos: FailedCheck[];
}

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

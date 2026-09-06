/** Tipos y API de Deteccion de Vulnerabilidades. */
import { api } from './api';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | '-';

export interface VulnItem {
  cve: string;
  severity: Severity;
  score: number | null;
  packageName: string;
  packageVersion: string;
  agent: string;
  os: string;
  description: string;
  detectedAt: string | null;
  publishedAt: string | null;
  reference: string | null;
  inKev: boolean;
  epss: number | null;
  priority: number;
}

export interface PrioritizedCve {
  cve: string;
  severity: Severity;
  score: number | null;
  inKev: boolean;
  kevDue: string | null;
  epss: number | null;
  epssPct: number | null;
  priority: number;
  instancias: number;
  agentes: number;
  description: string;
}

export interface VulnData {
  resumen: { total: number; critical: number; high: number; medium: number; low: number; agentes: number; cves: number; kev: number; exploitable: number };
  porSeveridad: { severity: Severity; count: number }[];
  topCve: { cve: string; count: number; severity: Severity; score: number | null; description: string; inKev: boolean; epss: number | null; priority: number }[];
  porAgente: { agent: string; total: number; critical: number; high: number }[];
  topPaquetes: { paquete: string; count: number }[];
  priorizadas: PrioritizedCve[];
  items: VulnItem[];
}

export interface IntelStatus {
  kevCount: number;
  epssCount: number;
  feeds: { name: string; last_run_at: string | null; last_count: number; last_status: string | null }[];
}

export const vulnApi = {
  get: () => api.get<VulnData>('/vulnerabilities').then((r) => r.data),
  intel: () => api.get<IntelStatus>('/vulnerabilities/intel').then((r) => r.data),
  refreshIntel: () => api.post<IntelStatus & { kev: number; epss: number }>('/vulnerabilities/intel/refresh').then((r) => r.data),
};

/** Color de la barra/etiqueta de prioridad por riesgo real. */
export function priorityBand(priority: number, inKev: boolean): { label: string; cls: string } {
  if (inKev) return { label: 'Urgente · KEV', cls: 'text-rose-700 bg-rose-500/10 border-rose-500/30' };
  if (priority >= 70) return { label: 'Alta', cls: 'text-orange-700 bg-orange-500/10 border-orange-500/30' };
  if (priority >= 45) return { label: 'Media', cls: 'text-amber-700 bg-amber-500/10 border-amber-500/30' };
  return { label: 'Baja', cls: 'text-slate-600 bg-slate-500/10 border-slate-500/30' };
}

export const SEV_COLOR: Record<Severity, string> = {
  Critical: '#dc2626',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  '-': '#94a3b8',
};

export const SEV_LABEL: Record<Severity, string> = {
  Critical: 'Crítica',
  High: 'Alta',
  Medium: 'Media',
  Low: 'Baja',
  '-': 'Sin sev.',
};

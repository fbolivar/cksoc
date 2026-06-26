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
}

export interface VulnData {
  resumen: { total: number; critical: number; high: number; medium: number; low: number; agentes: number; cves: number };
  porSeveridad: { severity: Severity; count: number }[];
  topCve: { cve: string; count: number; severity: Severity; score: number | null; description: string }[];
  porAgente: { agent: string; total: number; critical: number; high: number }[];
  topPaquetes: { paquete: string; count: number }[];
  items: VulnItem[];
}

export const vulnApi = {
  get: () => api.get<VulnData>('/vulnerabilities').then((r) => r.data),
};

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

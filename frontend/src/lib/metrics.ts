/** Cliente de métricas de operación del SOC (MTTD/MTTA/MTTR/SLA). */
import { api } from './api';

export type Severity = 'baja' | 'media' | 'alta' | 'critica';

export interface SocMetrics {
  window: { days: number; from: string };
  counts: { total: number; abierto: number; en_curso: number; resuelto: number; cerrado: number; bySeverity: Record<string, number> };
  quality: {
    realTotal: number;
    dispositions: { verdadero_positivo: number; falso_positivo: number; prueba: number; sin_clasificar: number };
    falsePositiveRate: number | null;
    excludedFromMetrics: number;
  };
  mttd: { avgMinutes: number | null; count: number };
  mtta: { avgMinutes: number | null; count: number };
  mttr: { avgMinutes: number | null; count: number };
  sla: {
    targets: Record<Severity, { responseMin: number; resolutionMin: number }>;
    overallPct: number | null;
    bySeverity: {
      severity: Severity; total: number;
      responseMet: number; responsePct: number | null;
      resolutionMet: number; resolutionEval: number; resolutionPct: number | null;
    }[];
  };
  aging: { openCount: number; oldestOpenHours: number | null; avgOpenAgeHours: number | null; openOver24h: number };
  throughput: { date: string; created: number; resolved: number }[];
}

export const metricsApi = {
  soc: (days = 30) => api.get<SocMetrics>('/metrics/soc', { params: { days } }).then((r) => r.data),
};

/** Formatea minutos como "12 min", "3.4 h" o "2.1 d". */
export function fmtDuration(min: number | null): string {
  if (min === null || min === undefined) return 'sin datos';
  if (min < 60) return `${Math.round(min)} min`;
  if (min < 1440) return `${(min / 60).toFixed(1)} h`;
  return `${(min / 1440).toFixed(1)} d`;
}

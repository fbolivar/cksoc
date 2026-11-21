/** Cliente del LLM Guardrail. */
import { api } from './api';

export interface GuardStats {
  dias: number;
  llamadasProtegidas: number;
  totalRedacciones: number;
  inyeccionesDetectadas: number;
  porCategoria: Record<string, number>;
  porTipoRedaccion: Record<string, number>;
}
export interface GuardEvent {
  id: string;
  createdAt: string;
  totalRedactions: number;
  injectionScore: number;
  categories: string[];
  samples: string[];
  owasp: string[];
}

export const llmGuardApi = {
  stats: (days = 30) => api.get<GuardStats>('/llm-guard/stats', { params: { days } }).then((r) => r.data),
  events: (limit = 50) => api.get<{ events: GuardEvent[] }>('/llm-guard/events', { params: { limit } }).then((r) => r.data.events),
};

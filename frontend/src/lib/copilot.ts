/** Copiloto IA: chat asistido, explicación de alertas y resumen de incidentes. */
import { api } from './api';

export interface ChatMessage { role: 'user' | 'assistant'; content: string }

export const copilotApi = {
  status: () => api.get<{ enabled: boolean }>('/copilot/status').then((r) => r.data),
  chat: (message: string, history: ChatMessage[]) =>
    api.post<{ reply: string; toolsUsed: string[] }>('/copilot/chat', { message, history }).then((r) => r.data),
  explain: (text: string) => api.post<{ reply: string }>('/copilot/explain', { text }).then((r) => r.data),
  triage: (text: string) => api.post<{ reply: string }>('/copilot/triage', { text }).then((r) => r.data),
  incidentSummary: (id: string) => api.post<{ reply: string }>(`/copilot/incident/${id}/summary`).then((r) => r.data),
};

/** Etiquetas legibles de las herramientas que el copiloto puede consultar. */
export const TOOL_LABEL: Record<string, string> = {
  buscar_alertas: 'alertas',
  top_vulnerabilidades: 'vulnerabilidades',
  anomalias_ueba: 'anomalías UEBA',
  incidentes_abiertos: 'incidentes',
  reputacion_ip: 'reputación de IP',
};

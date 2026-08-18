/** Copiloto IA: chat asistido, explicación de alertas y resumen de incidentes. */
import { api } from './api';

export interface ChatMessage { role: 'user' | 'assistant'; content: string }

// El copiloto agéntico (con herramientas) puede tardar bastante más que el
// timeout global de 15s de axios; se le da una ventana amplia (120s = igual que
// el proxy_read_timeout de Nginx) para que no se aborte a mitad de respuesta.
const LLM_TIMEOUT = { timeout: 120_000 };

export const copilotApi = {
  status: () => api.get<{ enabled: boolean }>('/copilot/status').then((r) => r.data),
  chat: (message: string, history: ChatMessage[]) =>
    api.post<{ reply: string; toolsUsed: string[] }>('/copilot/chat', { message, history }, LLM_TIMEOUT).then((r) => r.data),
  explain: (text: string) => api.post<{ reply: string }>('/copilot/explain', { text }, LLM_TIMEOUT).then((r) => r.data),
  triage: (text: string) => api.post<{ reply: string }>('/copilot/triage', { text }, LLM_TIMEOUT).then((r) => r.data),
  incidentSummary: (id: string) => api.post<{ reply: string }>(`/copilot/incident/${id}/summary`, undefined, LLM_TIMEOUT).then((r) => r.data),
};

/** Etiquetas legibles de las herramientas que el copiloto puede consultar. */
export const TOOL_LABEL: Record<string, string> = {
  buscar_alertas: 'alertas',
  top_vulnerabilidades: 'vulnerabilidades',
  anomalias_ueba: 'anomalías UEBA',
  incidentes_abiertos: 'incidentes',
  reputacion_ip: 'reputación de IP',
};

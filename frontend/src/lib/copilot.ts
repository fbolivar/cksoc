/** Copiloto IA: chat asistido, explicación de alertas y resumen de incidentes. */
import { api } from './api';

export interface ChatMessage { role: 'user' | 'assistant'; content: string }

export const copilotApi = {
  status: () => api.get<{ enabled: boolean }>('/copilot/status').then((r) => r.data),
  chat: (message: string, history: ChatMessage[]) =>
    api.post<{ reply: string }>('/copilot/chat', { message, history }).then((r) => r.data),
  explain: (text: string) => api.post<{ reply: string }>('/copilot/explain', { text }).then((r) => r.data),
  incidentSummary: (id: string) => api.post<{ reply: string }>(`/copilot/incident/${id}/summary`).then((r) => r.data),
};

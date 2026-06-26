/** API de Salud del SIEM. */
import { api } from './api';

export type Estado = 'ok' | 'warn' | 'fail';

export interface HealthComponent {
  id: string;
  nombre: string;
  estado: Estado;
  resumen: string;
  detalle?: string;
}

export interface AgentHealth {
  id: string;
  name: string;
  status: string;
  lastKeepAlive: string | null;
  minutosSinReportar: number | null;
  estado: Estado;
}

export interface SiemHealth {
  semaforo: 'verde' | 'amarillo' | 'rojo';
  generadoEn: string;
  componentes: HealthComponent[];
  agentes: AgentHealth[];
}

export interface HealthEvent {
  id: number;
  ts: string;
  componente: string;
  estado: Estado;
  detalle: string | null;
}

export const healthApi = {
  siem: (refresh = false) =>
    api.get<SiemHealth>(`/health/siem${refresh ? '?refresh=1' : ''}`).then((r) => r.data),
  history: (limit = 50) =>
    api.get<{ eventos: HealthEvent[] }>(`/health/history?limit=${limit}`).then((r) => r.data.eventos),
};

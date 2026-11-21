/** Cliente de Detección DDoS / Bots. */
import { api } from './api';

export interface TopSource { ip: string; flows: number; pais: string | null; publica: boolean; ioc: boolean }
export interface DdosSignal {
  tipo: 'fan-in' | 'amplificacion' | 'flood';
  target: string; sources: number; flows: number; topPort: number;
  protocol: string; appName: string; topSources: TopSource[];
  publicosTop: number; iocsTop: number;
  severidad: 'alta' | 'media' | 'baja'; descripcion: string;
}
export interface BotSignal {
  tipo: 'scraping' | 'credential-stuffing' | 'http-flood' | 'bot';
  source: string; target: string; flows: number; puertos: number; topPort: number;
  protocol: string; appName: string; pais: string | null; ioc: boolean;
  severidad: 'alta' | 'media' | 'baja'; descripcion: string;
}
export interface DdosReport {
  range: string; generadoEn: string;
  resumen: { flujos: number; volumetricos: number; bots: number };
  volumetric: DdosSignal[]; bots: BotSignal[];
}

export const ddosApi = {
  get: (range: string) => api.get<DdosReport>('/ddos', { params: { range } }).then((r) => r.data),
};

export const SEV: Record<string, string> = { alta: '#ef4444', media: '#f59e0b', baja: '#22c55e' };

/** Cliente de Exposición de APIs. */
import { api } from './api';

export interface ApiHallazgo { titulo: string; severidad: 'alta' | 'media' | 'baja'; owasp: string; evidencia: string }
export interface ApiEndpoint {
  id: string; host: string; ip: string | null; scheme: string; puerto: number;
  esApi: boolean; tipo: string; specExpuesto: boolean;
  hallazgos: ApiHallazgo[]; severidad: 'alta' | 'media' | 'baja'; primeraVez: string; ultimaVez: string;
}
export interface ApiExposureReport {
  ultimoScan: string | null;
  resumen: { total: number; apis: number; specsExpuestos: number; nuevos: number; zombies: number };
  endpoints: ApiEndpoint[];
}

export const apiExposureApi = {
  get: () => api.get<ApiExposureReport>('/api-exposure').then((r) => r.data),
  scan: () => api.post<{ hosts: number; apis: number; specs: number }>('/api-exposure/scan').then((r) => r.data),
};

export const SEV_COLOR: Record<string, string> = { alta: '#ef4444', media: '#f59e0b', baja: '#22c55e' };

/** API de Postura de Permisos / Compartición (M365). */
import { api } from './api';

export interface Guest { name: string; mail: string; domain: string; created: string | null; enabled: boolean; freeMail: boolean; stale: boolean }
export interface SiteShare { site: string; count: number }
export interface PermPosture {
  generatedAt: string; configured: boolean; range: string;
  kpis: { invitados: number; deshabilitados: number; dominios: number; correoGratis: number; enlacesAnonimos: number; invitExternas: number };
  invitados: Guest[]; dominios: { dominio: string; invitados: number }[];
  topSitiosAnonimos: SiteShare[]; recomendaciones: string[];
}

export const permPostureApi = {
  get: (days = '30d') => api.get<PermPosture>('/permposture', { params: { days } }).then((r) => r.data),
};

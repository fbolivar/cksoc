/** Cliente del Dossier de Incidente con IA. */
import { api } from './api';

export type EntType = 'ip' | 'host' | 'user' | 'domain';
export type ActionType = 'block_ip' | 'isolate_host' | 'force_mfa' | 'suppress_rule' | 'create_incident' | 'investigate';
export type Sev = 'critica' | 'alta' | 'media' | 'baja';
export type Conf = 'alta' | 'media' | 'baja';

export interface DossierAction { tipo: ActionType; objetivo: string; motivo: string; prioridad: number }
export interface DossierEntity { tipo: EntType; valor: string; rol: string; ioc: boolean }
export interface DossierTimeline { ts: string; evento: string; nivel: number; entidades: string[] }

export interface Dossier {
  id: string;
  generadoEn: string;
  seed: { type: EntType; value: string };
  incidentId: string | null;
  titulo: string;
  resumen: string;
  historia: string;
  severidad: Sev;
  confianza: Conf;
  causaRaiz: string;
  mitre: { id: string; nombre?: string }[];
  entidades: DossierEntity[];
  lineaTiempo: DossierTimeline[];
  acciones: DossierAction[];
  stats: { alertas: number; byType: Record<string, number> };
  geo: { ip: string; pais: string; ciudad: string } | null;
  modelo: string;
}

export const dossierApi = {
  generate: (type: EntType, value: string, opts: { range?: string; force?: boolean } = {}) =>
    api.post<Dossier>('/dossier/generate', { type, value, ...opts }).then((r) => r.data),
  forIncident: (id: string, force?: boolean) =>
    api.post<Dossier>(`/dossier/incident/${id}`, { force }).then((r) => r.data),
  recent: () => api.get<{ items: Dossier[] }>('/dossier/recent').then((r) => r.data.items),
};

export const SEV_COLOR: Record<Sev, string> = {
  critica: 'var(--hw-red, #ef4444)',
  alta: 'var(--hw-orange, #f59e0b)',
  media: 'var(--hw-teal, #14b8a6)',
  baja: 'var(--hw-green, #22c55e)',
};

export const ACTION_LABEL: Record<ActionType, string> = {
  block_ip: 'Bloquear IP',
  isolate_host: 'Aislar host',
  force_mfa: 'Forzar MFA / revisar identidad',
  suppress_rule: 'Afinar regla (falso positivo)',
  create_incident: 'Crear incidente',
  investigate: 'Investigar',
};

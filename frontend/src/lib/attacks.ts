/** Tipos y llamadas del mapa de ataques. */
import { api } from './api';

export type Clasificacion = 'malicioso' | 'sospechoso' | 'usuario' | 'desconocido';

export interface AttackOrigin {
  country: string;
  city: string;
  isoCode: string;
  lat: number;
  lon: number;
  count: number;
  severity_max: number;
  last_seen: string;
  ips: string[];
  isp: string | null;
  usageType: string | null;
  abuseScore: number;
  clasificacion: Clasificacion;
  esExterno: boolean;
}

export interface Destination {
  name: string;
  lat: number;
  lon: number;
}

export interface AttackGeoResponse {
  hours: number;
  destination: Destination;
  origins: AttackOrigin[];
  threatIntel: boolean;
}

/** Color por clasificacion de origen (no por severidad de regla). */
export const CLASIF: Record<Clasificacion, { color: string; label: string }> = {
  malicioso: { color: '#ef4444', label: 'Malicioso' },
  sospechoso: { color: '#f97316', label: 'Sospechoso' },
  usuario: { color: '#22c55e', label: 'Usuario' },
  desconocido: { color: '#94a3b8', label: 'Sin datos' },
};

export interface NewAttack {
  ip: string;
  country: string;
  city: string;
  isoCode: string;
  lat: number;
  lon: number;
  severity: number;
  description: string;
  ts: string;
}

export const attacksApi = {
  geo: (hours: number) =>
    api.get<AttackGeoResponse>('/attacks/geo', { params: { hours } }).then((r) => r.data),
};

/** Color segun severidad maxima (verde -> amarillo -> naranja -> rojo). */
export function severityColor(level: number): string {
  if (level >= 12) return '#ef4444';
  if (level >= 8) return '#f97316';
  if (level >= 5) return '#eab308';
  return '#22c55e';
}

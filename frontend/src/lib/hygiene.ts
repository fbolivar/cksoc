/** Tipos y API de IT Hygiene (inventario de endpoints). */
import { api } from './api';

export type HostKind = 'servidor' | 'estacion';
export interface HostInfo {
  agent: string; hostname: string; os: string; arch: string;
  cpu: string; cores: number; ramGB: number;
  packages: number; ports: number; users: number; hotfixes: number;
  kind: HostKind; hygieneScore: number; flags: string[]; needsAttention: boolean;
}
export interface Summary { kpis: Record<string, number>; hosts: HostInfo[]; outliers: HostInfo[] }
export interface PortRow { agent: string; port: number; transport: string; ip: string; process: string }
export interface SoftwareRow { name: string; vendor: string; hosts: number }
export interface UserRow { agent: string; name: string; fullName: string; hidden: boolean; remote: boolean; groups: string[]; authFailures: number }
export interface UsersData { porAgente: { agent: string; count: number }[]; riesgo: UserRow[] }
export interface HotfixRow { agent: string; count: number; recientes: string[] }

export const hygieneApi = {
  summary: () => api.get<Summary>('/hygiene/summary').then((r) => r.data),
  ports: () => api.get<PortRow[]>('/hygiene/ports').then((r) => r.data),
  software: () => api.get<SoftwareRow[]>('/hygiene/software').then((r) => r.data),
  users: () => api.get<UsersData>('/hygiene/users').then((r) => r.data),
  hotfixes: () => api.get<HotfixRow[]>('/hygiene/hotfixes').then((r) => r.data),
};

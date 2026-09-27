/** API del módulo Flujos de red (analítica NetFlow/QFlow del SonicWall). */
import { api } from './api';

export interface FlowsOverview {
  range: string; flows: number;
  timeline: { ts: string; flows: number }[];
  topTalkers: { ip: string; flows: number; destinos: number }[];
  topDst: { ip: string; flows: number; talker: string; pais: string | null; ioc: boolean }[];
  topPorts: { port: string; flows: number }[];
  topApps: { app: string; flows: number }[];
}
export interface Beacon { src: string; dst: string; flows: number; intervaloSeg: number; regularidad: number; pais: string | null; ioc: boolean }
export interface ScanSrc { src: string; destinos: number; puertos: number; flows: number; nivel: 'alto' | 'medio'; tipo: string; pais: string | null }

export const flowsApi = {
  overview: (range = '24h') => api.get<FlowsOverview>('/flows/overview', { params: { range } }).then((r) => r.data),
  beaconing: (range = '24h') => api.get<{ beacons: Beacon[] }>('/flows/beaconing', { params: { range } }).then((r) => r.data.beacons),
  scans: (range = '24h') => api.get<{ scans: ScanSrc[] }>('/flows/scans', { params: { range } }).then((r) => r.data.scans),
};

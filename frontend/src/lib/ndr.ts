/** Cliente NDR (visibilidad de red vía FortiGate). */
import { api } from './api';

export interface NdrTalker { ip: string; sessions: number; dstIps: number }
export interface NdrDomain { domain: string; count: number }
export interface NdrApp { app: string; count: number }
export interface NdrDst { ip: string; count: number }
export interface NdrIps { ts: string; srcip: string | null; dstip: string | null; msg: string; action: string; severity: string | null; attack: string | null }
export interface NdrIoc { type: string; value: string; source: string; confidence: number; seen: 'domain' | 'ip' }

export interface NdrOverview {
  range: string;
  sessions: number;
  distinctDomains: number;
  distinctDstIps: number;
  ipsCount: number;
  topTalkers: NdrTalker[];
  topDomains: NdrDomain[];
  topApps: NdrApp[];
  topDstIps: NdrDst[];
  ipsAlerts: NdrIps[];
  iocHits: NdrIoc[];
  generatedAt: string;
}

export const ndrApi = {
  overview: (range: string) => api.get<NdrOverview>('/ndr', { params: { range } }).then((r) => r.data),
};

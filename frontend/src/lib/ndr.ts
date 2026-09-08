/** Cliente NDR (visibilidad de red vía FortiGate). */
import { api } from './api';

export interface NdrTalker { ip: string; sessions: number; dstIps: number }
export interface NdrDomain { domain: string; count: number }
export interface NdrApp { app: string; count: number }
export interface NdrDst { ip: string; count: number }
export interface NdrIps { ts: string; srcip: string | null; dstip: string | null; msg: string; action: string; severity: string | null; attack: string | null }
export interface NdrIoc { type: string; value: string; source: string; confidence: number; seen: 'domain' | 'ip' }
export interface NdrTransfer {
  ts: string; srcip: string | null; dstip: string | null; sentbyte: number; rcvdbyte: number;
  dstport: string | null; service: string | null; duration: number; appcat: string | null;
  dstcountry: string | null; sessionid: string | null;
  srcHost: string | null; srcOs: string | null; srcUser: string | null;
  dstDomain: string | null; dstVerdict: string | null; dstIsp: string | null; dstAbuse: number | null; dstIoc: boolean;
  trusted: boolean; riskRank: number;
}

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
  largeTransfers: NdrTransfer[];
  largeTransferCount: number;
  generatedAt: string;
}

export const ndrApi = {
  overview: (range: string) => api.get<NdrOverview>('/ndr', { params: { range } }).then((r) => r.data),
};

// --- NPM: rendimiento de interfaces (FortiGate) ---
export interface NetIface {
  name: string; alias: string | null; ip: string | null; link: boolean; speedMbps: number;
  inBps: number; outBps: number; utilPct: number; peakUtilPct: number; flaps: number;
  txErrors: number; rxErrors: number; spark: number[];
}
export interface NetLive { polling: boolean; lastPollAt: number | null; pollSeconds: number; interfaces: NetIface[] }

export const netperfApi = {
  interfaces: () => api.get<NetLive>('/netperf/interfaces').then((r) => r.data),
};

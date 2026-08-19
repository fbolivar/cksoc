/** Cliente del dashboard Office 365. */
import { api } from './api';

export interface NamedCount { key: string; count: number; country?: string }
export interface RuleCount { desc: string; count: number; level: number }
export interface TimePoint { ts: number; count: number }

export interface O365Overview {
  range: string;
  total: number;
  users: number;
  clientIps: number;
  signIns: number;
  signInsFailed: number;
  downloads: number;
  timeline: TimePoint[];
  topUsers: NamedCount[];
  topClientIps: NamedCount[];
  topOperations: NamedCount[];
  workloads: NamedCount[];
  topRules: RuleCount[];
  signInUsers: NamedCount[];
  signInIps: NamedCount[];
  fileTopUsers: NamedCount[];
  generatedAt: string;
}

export const office365Api = {
  overview: (range: string) => api.get<O365Overview>('/office365', { params: { range } }).then((r) => r.data),
};

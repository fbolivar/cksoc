/** Cliente del módulo Postura de correo (SPF/DKIM/DMARC/MX + reportes DMARC). */
import { api } from './api';

export type Grade = 'ok' | 'warn' | 'fail' | 'missing';
export interface Fix { title: string; record?: string; where: string }
export interface Check {
  key: 'spf' | 'dkim' | 'dmarc' | 'mx';
  label: string; grade: Grade; value: string | null; summary: string; findings: string[]; fix?: Fix;
}
export interface DomainPosture { domain: string; score: number; grade: Grade; checks: Check[]; generatedAt: string }

export interface DmarcReadiness {
  ready: boolean; graphConfigured: boolean; mailReadScope: boolean; mailbox: string | null;
  missing: { step: string; detail: string }[];
}
export interface PostureResponse { domains: DomainPosture[]; dmarcReadiness: DmarcReadiness; generatedAt: string }

export interface DmarcSource { ip: string; count: number; pass: number; fail: number; disposition: string }
export interface DmarcReportSummary {
  ready: boolean; readiness: DmarcReadiness; reports: number; totalMessages: number;
  aligned: number; failing: number; passRate: number;
  sources: DmarcSource[]; reporters: { name: string; count: number }[];
  window: { from: string; to: string } | null; generatedAt: string;
}

export const emailPostureApi = {
  posture: (domain?: string) => api.get<PostureResponse>('/email-posture', { params: domain ? { domain } : {} }).then((r) => r.data),
  dmarc: (days = 14) => api.get<DmarcReportSummary>('/email-posture/dmarc', { params: { days } }).then((r) => r.data),
};

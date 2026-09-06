/** Cliente de licenciamiento. */
import { AxiosError } from 'axios';
import { api } from './api';

export type LicenseState = 'active' | 'grace' | 'expired' | 'none' | 'invalid';
export type LicenseUrgency = 'none' | 'info' | 'warn' | 'urgent';
export interface LicenseStatus {
  state: LicenseState;
  message: string;
  customer?: string;
  issuedAt?: string;
  expiresAt?: string;
  daysLeft?: number;
  clockWarning?: boolean;
  renewalWarning?: boolean;
  urgency?: LicenseUrgency;
  graceDaysLeft?: number;
}

let cached: { at: number; data: LicenseStatus } | null = null;

export async function fetchLicenseStatus(force = false): Promise<LicenseStatus> {
  if (!force && cached && Date.now() - cached.at < 20_000) return cached.data;
  const data = (await api.get<LicenseStatus>('/license/status')).data;
  cached = { at: Date.now(), data };
  return data;
}

export async function activateLicense(code: string): Promise<LicenseStatus> {
  try {
    const data = (await api.post<LicenseStatus>('/license/activate', { code })).data;
    cached = { at: Date.now(), data };
    return data;
  } catch (e) {
    const body = (e as AxiosError<LicenseStatus>).response?.data;
    if (body && body.state) { cached = { at: Date.now(), data: body }; return body; }
    throw e;
  }
}

export function clearLicenseCache(): void { cached = null; }

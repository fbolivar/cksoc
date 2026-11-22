/** API del Monitor de Consentimientos OAuth (M365). */
import { api } from './api';

export type Risk = 'critica' | 'alta' | 'media' | 'baja';
export interface OAuthApp {
  appId: string; spId: string; name: string; publisher: string | null; verified: boolean; firstParty: boolean;
  consent: 'organizacion' | 'usuario'; usuarios: number; scopes: string[]; appRoles: string[]; mailAccess: boolean;
  risk: Risk; score: number; reasons: string[];
}
export interface OAuthOverview {
  generatedAt: string; configured: boolean;
  kpis: { total: number; terceros: number; riesgosas: number; sinEditor: number; orgConsent: number; conCorreo: number };
  apps: OAuthApp[];
}

export const oauthAppsApi = {
  get: () => api.get<OAuthOverview>('/oauth-apps').then((r) => r.data),
  refresh: () => api.post<{ ok: boolean; nuevas: number }>('/oauth-apps/refresh', {}, { timeout: 60_000 }).then((r) => r.data),
};

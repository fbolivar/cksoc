/** API del Generador de Takedown. */
import { api } from './api';

export interface Candidate { id: string; domain: string; brand: string; tecnica: string; mx: boolean; ips: string[]; severidad: string; primeraVez: string; ultimaVez: string; detalle: string }
export interface TakedownRecipient { tipo: string; email: string }
export interface TakedownPackage {
  domain: string; brand: string; registrar: string | null; hosting: string | null;
  recipients: TakedownRecipient[]; subject: string; body: string;
  evidence: { tecnica: string; mx: boolean; ips: string[]; primeraVez: string | null; ultimaVez: string | null };
  aviso: string;
}

export const takedownApi = {
  candidates: () => api.get<Candidate[]>('/takedown/candidates').then((r) => r.data),
  generate: (domain: string) => api.post<TakedownPackage>('/takedown/generate', { domain }, { timeout: 60_000 }).then((r) => r.data),
};

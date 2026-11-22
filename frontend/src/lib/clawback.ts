/** API del Claw-back post-entrega (M365). */
import { api } from './api';

export interface Criteria { sender?: string; subject?: string; internetMessageId?: string; days?: number }
export interface MsgHit { id: string; subject: string; from: string; received: string }
export interface MailboxResult { upn: string; count: number; samples: MsgHit[]; moved?: number; error?: string }
export interface ClawPreview { ok: boolean; mailboxes: number; totalMatches: number; afectados: number; criterios: Criteria; resultados: MailboxResult[]; error?: string }

export const clawbackApi = {
  preview: (c: Criteria) => api.post<ClawPreview>('/clawback/preview', c, { timeout: 120_000 }).then((r) => r.data),
  execute: (c: Criteria) => api.post<ClawPreview>('/clawback/execute', { ...c, confirm: 'CONFIRMAR' }, { timeout: 180_000 }).then((r) => r.data),
};

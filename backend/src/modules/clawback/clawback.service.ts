/**
 * Claw-back post-entrega (M365) — localiza un correo malicioso en TODOS los buzones y
 * lo mueve a Elementos eliminados (soft-delete REVERSIBLE). Es la "remediación
 * automática" post-entrega. Vía Microsoft Graph (Mail.ReadWrite, app existente).
 *
 * SEGURIDAD: preview() es solo lectura; execute() es acción destructiva (admin, con
 * confirmación), usa soft-delete (recuperable por el usuario), y queda auditada.
 */
import axios, { type AxiosResponse } from 'axios';
import { logger } from '../../config/logger';
import { env } from '../../config/env';

export function isGraphConfigured(): boolean { return Boolean(env.GRAPH_TENANT_ID && env.GRAPH_CLIENT_ID && env.GRAPH_CLIENT_SECRET); }
let tok: { token: string; exp: number } | null = null;
async function graphToken(): Promise<string> {
  if (tok && Date.now() < tok.exp) return tok.token;
  const body = new URLSearchParams({ client_id: env.GRAPH_CLIENT_ID!, client_secret: env.GRAPH_CLIENT_SECRET!, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' });
  const { data } = await axios.post<{ access_token: string; expires_in: number }>(`https://login.microsoftonline.com/${env.GRAPH_TENANT_ID}/oauth2/v2.0/token`, body.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 12_000 });
  tok = { token: data.access_token, exp: Date.now() + (data.expires_in - 60) * 1000 };
  return data.access_token;
}
const G = axios.create({ baseURL: 'https://graph.microsoft.com/v1.0', timeout: 20_000 });

export interface Criteria { sender?: string; subject?: string; internetMessageId?: string; days?: number }
export interface MsgHit { id: string; subject: string; from: string; received: string }
export interface MailboxResult { upn: string; count: number; samples: MsgHit[]; moved?: number; error?: string }
export interface ClawPreview { ok: boolean; mailboxes: number; totalMatches: number; afectados: number; criterios: Criteria; resultados: MailboxResult[]; error?: string }

function esc(s: string): string { return s.replace(/'/g, "''"); }
function buildFilter(c: Criteria): string {
  if (c.internetMessageId) return `internetMessageId eq '${esc(c.internetMessageId.trim())}'`;
  const parts: string[] = [];
  if (c.sender) parts.push(`from/emailAddress/address eq '${esc(c.sender.trim().toLowerCase())}'`);
  const days = Math.min(30, Math.max(1, c.days ?? 7));
  parts.push(`receivedDateTime ge ${new Date(Date.now() - days * 86400000).toISOString()}`);
  return parts.join(' and ');
}

async function mailboxes(token: string): Promise<{ id: string; upn: string }[]> {
  const out: { id: string; upn: string }[] = [];
  let url: string | null = '/users?$select=id,userPrincipalName,mail,accountEnabled&$top=999';
  while (url) {
    const resp: AxiosResponse<{ value?: { id: string; userPrincipalName: string; mail?: string; accountEnabled?: boolean }[]; '@odata.nextLink'?: string }> =
      await G.get(url, { headers: { Authorization: `Bearer ${token}` } });
    for (const u of resp.data.value ?? []) if (u.mail && u.accountEnabled !== false) out.push({ id: u.id, upn: u.userPrincipalName });
    const nxt: string | undefined = resp.data['@odata.nextLink'];
    url = nxt ? nxt.replace('https://graph.microsoft.com/v1.0', '') : null;
  }
  return out;
}

async function searchMailbox(token: string, userId: string, c: Criteria): Promise<MsgHit[]> {
  const filter = encodeURIComponent(buildFilter(c));
  const resp: AxiosResponse<{ value?: { id: string; subject?: string; from?: { emailAddress?: { address?: string } }; receivedDateTime?: string }[] }> =
    await G.get(`/users/${userId}/messages?$filter=${filter}&$top=50&$select=id,subject,from,receivedDateTime`, { headers: { Authorization: `Bearer ${token}` } });
  let msgs = resp.data.value ?? [];
  if (c.subject) { const s = c.subject.trim().toLowerCase(); msgs = msgs.filter((m) => (m.subject ?? '').toLowerCase().includes(s)); }
  return msgs.map((m) => ({ id: m.id, subject: m.subject ?? '(sin asunto)', from: m.from?.emailAddress?.address ?? '?', received: m.receivedDateTime ?? '' }));
}

function valid(c: Criteria): boolean { return Boolean(c.internetMessageId || c.sender); }

/** PREVIEW — solo lectura: en qué buzones está el mensaje. NO borra. */
export async function preview(c: Criteria): Promise<ClawPreview> {
  if (!isGraphConfigured()) return { ok: false, mailboxes: 0, totalMatches: 0, afectados: 0, criterios: c, resultados: [], error: 'Graph no configurado' };
  if (!valid(c)) return { ok: false, mailboxes: 0, totalMatches: 0, afectados: 0, criterios: c, resultados: [], error: 'Indica al menos remitente o internetMessageId' };
  const token = await graphToken();
  const boxes = await mailboxes(token);
  const resultados: MailboxResult[] = [];
  let total = 0;
  for (const b of boxes) {
    try {
      const hits = await searchMailbox(token, b.id, c);
      if (hits.length) { total += hits.length; resultados.push({ upn: b.upn, count: hits.length, samples: hits.slice(0, 3) }); }
    } catch (e) { logger.warn({ err: (e as Error).message, upn: b.upn }, 'clawback: preview mailbox'); }
  }
  resultados.sort((a, b) => b.count - a.count);
  return { ok: true, mailboxes: boxes.length, totalMatches: total, afectados: resultados.length, criterios: c, resultados };
}

/** EXECUTE — mueve a Elementos eliminados (soft-delete) en cada buzón. Destructivo (admin). */
export async function execute(c: Criteria, actor: string): Promise<ClawPreview> {
  if (!isGraphConfigured()) return { ok: false, mailboxes: 0, totalMatches: 0, afectados: 0, criterios: c, resultados: [], error: 'Graph no configurado' };
  if (!valid(c)) return { ok: false, mailboxes: 0, totalMatches: 0, afectados: 0, criterios: c, resultados: [], error: 'Criterios insuficientes' };
  const token = await graphToken();
  const boxes = await mailboxes(token);
  const resultados: MailboxResult[] = [];
  let totalMoved = 0;
  for (const b of boxes) {
    try {
      const hits = await searchMailbox(token, b.id, c);
      if (!hits.length) continue;
      let moved = 0; let err: string | undefined;
      for (const h of hits) {
        try { await G.post(`/users/${b.id}/messages/${h.id}/move`, { destinationId: 'deleteditems' }, { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }); moved++; }
        catch (e) { err = (e as Error).message; }
      }
      totalMoved += moved;
      resultados.push({ upn: b.upn, count: hits.length, samples: hits.slice(0, 3), moved, error: err });
    } catch (e) { resultados.push({ upn: b.upn, count: 0, samples: [], moved: 0, error: (e as Error).message }); }
  }
  resultados.sort((a, b) => (b.moved ?? 0) - (a.moved ?? 0));
  logger.warn({ actor, criterios: c, buzonesAfectados: resultados.length, correosMovidos: totalMoved }, '🧹 CLAW-BACK ejecutado (soft-delete a Elementos eliminados)');
  return { ok: true, mailboxes: boxes.length, totalMatches: totalMoved, afectados: resultados.length, criterios: c, resultados };
}

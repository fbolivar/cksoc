/**
 * Anti-BEC (Business Email Compromise) vía Microsoft Graph + auditoría O365.
 * NO es un gateway inline: es detección de lectura + alerta (no afecta el flujo
 * de correo). Dos frentes:
 *   A) REENVÍO / REGLAS (persistencia BEC) — por la auditoría que ya ingesta
 *      Wazuh: New-InboxRule/Set-InboxRule/*-TransportRule y Set-Mailbox con
 *      ForwardingSmtpAddress a un dominio externo. (messageRules/mailboxSettings
 *      de Graph dan 403 con los permisos actuales; el audit sí llega.)
 *   B) URLs / ADJUNTOS maliciosos en correo reciente — vía Graph (Mail.ReadWrite),
 *      acotado a los buzones bajo ataque (o BEC_SCAN_MAILBOXES), cruzando contra
 *      el catálogo de IOCs y marcando adjuntos peligrosos.
 */
import crypto from 'node:crypto';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
type Sev = 'critica' | 'alta' | 'media';

const MAIL_HOURS = Number(env.BEC_MAIL_HOURS) || 24;
const MAX_MAILBOXES = Number(env.BEC_MAIL_MAX_MAILBOXES) || 25;
const MAX_MSGS = Number(env.BEC_MAIL_MAX_MSGS) || 40;
const FINANCE_KW = /(invoice|payment|wire|transfer|bank|swift|iban|factura|pago|transferencia|banco|remesa|beneficiar|routing|\bctas?\b|cuenta\s*(bancaria|no|numero))/i;
const DANGER_EXT = new Set(['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'lnk', 'iso', 'img', 'hta', 'htm', 'html', 'jar', 'ps1', 'bat', 'cmd', 'com', 'pif', 'msi', 'msc', 'xll', 'docm', 'xlsm', 'pptm', 'one', 'svg']);
const URL_RE = /https?:\/\/[^\s"'<>)\]}]+/gi;
const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
// Plataformas de hosting compartido/CDN legítimas: no accionables como IOC de dominio
// (mismo criterio que NDR/ThreatIntel). Evita falsos positivos con newsletters.
const LEGIT_HOSTING_RE = /(^|\.)(github|githubusercontent|google|googleapis|googleusercontent|gstatic|youtube|discord|discordapp|cloudinary|imgur|ibb|firebasestorage|licdn|linkedin|microsoft|office365?|windows|live|amazonaws|cloudfront|dropbox|apple|icloud|cloudflare|akamai|fastly|bitbucket|gitlab|wetransfer|whatsapp|facebook|fbcdn|sharepoint|onedrive|outlook|sendgrid|mailchimp|mandrillapp|sparkpostmail|hubspot)\.[a-z]{2,}(\.[a-z]{2,})?$/i;

export function isBecEnabled(): boolean {
  return String(env.BEC_ENABLED ?? 'true').toLowerCase() !== 'false';
}

// ---- Graph (client credentials) ----
let tok: { t: string; exp: number } | null = null;
async function graphToken(): Promise<string> {
  if (tok && Date.now() < tok.exp) return tok.t;
  const body = new URLSearchParams({ client_id: env.GRAPH_CLIENT_ID ?? '', client_secret: env.GRAPH_CLIENT_SECRET ?? '', scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' });
  const r = await fetch(`https://login.microsoftonline.com/${env.GRAPH_TENANT_ID}/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json() as { access_token?: string; expires_in?: number };
  if (!j.access_token) throw new HttpError(503, 'Graph no configurado o sin acceso');
  tok = { t: j.access_token, exp: Date.now() + (j.expires_in ?? 3600) * 1000 - 60_000 };
  return tok.t;
}
function graphConfigured(): boolean { return !!(env.GRAPH_CLIENT_ID && env.GRAPH_CLIENT_SECRET && env.GRAPH_TENANT_ID); }
async function gget<T>(path: string): Promise<{ status: number; data: T }> {
  const t = await graphToken();
  const r = await fetch('https://graph.microsoft.com/v1.0' + path, { headers: { Authorization: 'Bearer ' + t } });
  let data: unknown = {}; try { data = await r.json(); } catch { /* vacío */ }
  return { status: r.status, data: data as T };
}

async function internalDomains(): Promise<Set<string>> {
  const set = new Set<string>((env.BEC_INTERNAL_DOMAINS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
  try {
    const { status, data } = await gget<{ value?: { id: string }[] }>('/domains?$select=id');
    if (status === 200) for (const d of data.value ?? []) if (d.id) set.add(d.id.toLowerCase());
  } catch { /* usa env */ }
  return set;
}
function isExternal(email: string, internal: Set<string>): boolean {
  const dom = email.split('@')[1]?.toLowerCase();
  return !!dom && !internal.has(dom);
}

// ---- persistencia ----
async function addFinding(f: { tipo: string; usuario: string; ref: string; severidad: Sev; detalle: string; meta: unknown }): Promise<boolean> {
  const rows = await query<{ nuevo: boolean }>(
    `INSERT INTO bec_findings (tipo, usuario, ref, severidad, detalle, meta, estado, ultima_vez)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,'open', now())
     ON CONFLICT (usuario, tipo, ref) DO UPDATE
       SET severidad=EXCLUDED.severidad, detalle=EXCLUDED.detalle, meta=EXCLUDED.meta, ultima_vez=now(),
           estado = CASE WHEN bec_findings.estado='dismissed' THEN 'dismissed' ELSE 'open' END
     RETURNING (xmax = 0) AS nuevo`,
    [f.tipo, f.usuario, f.ref, f.severidad, f.detalle, JSON.stringify(f.meta)],
  );
  return rows[0]?.nuevo ?? false;
}

export interface BecNew { usuario: string; tipo: string; severidad: Sev; detalle: string }
export interface BecScan { window: string; reglas: number; correoRevisado: number; hallazgos: number; nuevos: number; nuevosList: BecNew[] }

// ---- A) auditoría: reenvíos y reglas ----
interface AuditHit { _source: { '@timestamp': string; data?: { office365?: { Operation?: string; UserId?: string; ObjectId?: string; ClientIP?: string; Parameters?: { Name?: string; Value?: string }[] } } } }
async function scanAudit(gte: string, internal: Set<string>, track: (u: string, tipo: string, ref: string, sev: Sev, detalle: string, meta: unknown) => Promise<boolean>): Promise<number> {
  const { data } = await getIndexerClient().post<{ hits: { hits: AuditHit[] } }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 200,
    query: { bool: { filter: [{ range: { '@timestamp': { gte } } }, { terms: { 'data.office365.Operation': ['New-InboxRule', 'Set-InboxRule', 'New-TransportRule', 'Set-TransportRule', 'Set-Mailbox'] } }] } },
    sort: [{ '@timestamp': { order: 'desc' } }],
    _source: ['@timestamp', 'data.office365.Operation', 'data.office365.UserId', 'data.office365.ObjectId', 'data.office365.ClientIP', 'data.office365.Parameters'],
  });
  let n = 0;
  for (const h of data.hits.hits) {
    const o = h._source.data?.office365; if (!o?.Operation) continue;
    const actor = o.UserId ?? '';
    if (/NT SERVICE|MSExchange/i.test(actor)) continue; // provisioning del sistema
    const params = new Map((o.Parameters ?? []).map((p) => [String(p.Name), String(p.Value ?? '')]));
    const usuario = o.ObjectId || actor;
    if (o.Operation === 'Set-Mailbox') {
      const fwd = params.get('ForwardingSmtpAddress') || params.get('ForwardingAddress') || '';
      if (!fwd) continue; // los Set-Mailbox de provisioning no traen forwarding
      const emails = fwd.match(EMAIL_RE) ?? [];
      const ext = emails.some((e) => isExternal(e, internal));
      const sev: Sev = ext ? 'critica' : 'alta';
      if (await track(usuario, 'mailbox_forwarding', 'setmbx', sev, `Reenvío automático de buzón configurado hacia ${fwd}${ext ? ' (EXTERNO)' : ''}`, { fwd, external: ext, actor })) n++;
      continue;
    }
    // reglas de bandeja / transporte
    const targets = ['ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo', 'BlindCopyTo', 'RedirectMessageTo', 'CopyTo']
      .flatMap((k) => (params.get(k) || '').match(EMAIL_RE) ?? []);
    const extTargets = targets.filter((e) => isExternal(e, internal));
    const hides = ['DeleteMessage', 'MarkAsRead'].some((k) => /true/i.test(params.get(k) || '')) || params.has('MoveToFolder');
    const kw = FINANCE_KW.test([...params.values()].join(' '));
    if (extTargets.length) {
      if (await track(usuario, 'forwarding_rule', o.Operation + ':ext', 'critica', `Regla "${o.Operation}" reenvía correo a EXTERNO: ${extTargets.join(', ')}${kw ? ' + palabras financieras' : ''}`, { operation: o.Operation, targets: extTargets, finance: kw, actor })) n++;
    } else if (hides && kw) {
      if (await track(usuario, 'forwarding_rule', o.Operation + ':hide', 'alta', `Regla "${o.Operation}" oculta correos (borra/marca leído/mueve) filtrando por palabras financieras — patrón de ocultamiento BEC`, { operation: o.Operation, finance: kw, actor })) n++;
    } else if (targets.length) {
      if (await track(usuario, 'forwarding_rule', o.Operation + ':fwd', 'media', `Regla "${o.Operation}" reenvía/copia correo a ${targets.join(', ')}`, { operation: o.Operation, targets, actor })) n++;
    }
  }
  return n;
}

// ---- B) Graph: URLs y adjuntos en correo reciente ----
interface GMsg { id: string; subject?: string; from?: { emailAddress?: { address?: string } }; receivedDateTime?: string; webLink?: string; hasAttachments?: boolean; body?: { content?: string } }
interface GAtt { '@odata.type'?: string; name?: string; contentType?: string; size?: number; contentBytes?: string }

async function scanMailboxes(scope: string[], iocDomains: Set<string>, iocUrls: Set<string>, iocHashes: Set<string>, track: (u: string, tipo: string, ref: string, sev: Sev, detalle: string, meta: unknown) => Promise<boolean>): Promise<{ revisados: number; nuevos: number }> {
  const sinceIso = new Date(Date.now() - MAIL_HOURS * 3600_000).toISOString();
  let revisados = 0, nuevos = 0;
  for (const mbx of scope.slice(0, MAX_MAILBOXES)) {
    try {
      const { status, data } = await gget<{ value?: GMsg[] }>(`/users/${encodeURIComponent(mbx)}/messages?$top=${MAX_MSGS}&$select=id,subject,from,receivedDateTime,webLink,hasAttachments,body&$filter=${encodeURIComponent('receivedDateTime ge ' + sinceIso)}`);
      if (status !== 200) { if (status !== 404) logger.warn({ mbx, status }, 'BEC: no se pudo leer buzón'); continue; }
      for (const m of data.value ?? []) {
        revisados++;
        const from = m.from?.emailAddress?.address ?? '';
        // URLs en el cuerpo
        const html = m.body?.content ?? '';
        const urls = [...new Set((html.match(URL_RE) ?? []).map((u) => u.replace(/&amp;/g, '&')))].slice(0, 60);
        for (const u of urls) {
          let host = ''; try { host = new URL(u).hostname.toLowerCase(); } catch { /* url rara */ }
          if (!host || LEGIT_HOSTING_RE.test(host)) continue;
          const hostBad = iocDomains.has(host) || [...iocDomains].some((d) => host.endsWith('.' + d));
          if (iocUrls.has(u) || hostBad) {
            if (await track(mbx, 'mail_bad_url', 'url:' + host, 'alta', `Correo de ${from} ("${(m.subject || '').slice(0, 60)}") contiene URL maliciosa conocida: ${host}`, { from, subject: m.subject, url: u, host, receivedDateTime: m.receivedDateTime, webLink: m.webLink })) nuevos++;
            break;
          }
        }
        // Adjuntos
        if (m.hasAttachments) {
          const att = await gget<{ value?: GAtt[] }>(`/users/${encodeURIComponent(mbx)}/messages/${m.id}/attachments?$select=name,contentType,size,contentBytes`);
          if (att.status === 200) for (const a of att.data.value ?? []) {
            const name = a.name ?? '';
            const ext = name.split('.').pop()?.toLowerCase() ?? '';
            let sha = '';
            if (a.contentBytes && (a.size ?? 0) <= 8_000_000) { try { sha = crypto.createHash('sha256').update(Buffer.from(a.contentBytes, 'base64')).digest('hex'); } catch { /* noop */ } }
            if (sha && iocHashes.has(sha)) {
              if (await track(mbx, 'mail_bad_attachment', 'att:' + sha.slice(0, 16), 'critica', `Correo de ${from} trae adjunto "${name}" cuyo hash coincide con malware conocido (IOC)`, { from, subject: m.subject, name, sha256: sha, receivedDateTime: m.receivedDateTime, webLink: m.webLink })) nuevos++;
            } else if (DANGER_EXT.has(ext)) {
              if (await track(mbx, 'mail_bad_attachment', 'att:ext:' + ext + ':' + name.slice(0, 40), 'media', `Correo de ${from} trae adjunto de tipo peligroso "${name}" (.${ext})`, { from, subject: m.subject, name, ext, receivedDateTime: m.receivedDateTime, webLink: m.webLink })) nuevos++;
            }
          }
        }
      }
    } catch (e) { logger.warn({ err: e instanceof Error ? e.message : e, mbx }, 'BEC: fallo escaneando buzón'); }
  }
  return { revisados, nuevos };
}

async function scanScope(): Promise<string[]> {
  const env_list = (env.BEC_SCAN_MAILBOXES || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (env_list.length) return env_list;
  // por defecto: cuentas bajo exposición/ataque (credexp)
  const rows = await query<{ email: string }>("SELECT (alias || '@' || domain) AS email FROM credexp_accounts WHERE estado <> 'dismissed'").catch(() => [] as { email: string }[]);
  return rows.map((r) => r.email);
}

export async function scan(rangeIn = '7d'): Promise<BecScan> {
  const range = RANGE[rangeIn] ? rangeIn : '7d';
  const nuevosList: BecNew[] = [];
  const track = async (usuario: string, tipo: string, ref: string, severidad: Sev, detalle: string, meta: unknown): Promise<boolean> => {
    const nuevo = await addFinding({ tipo, usuario, ref, severidad, detalle, meta });
    if (nuevo) nuevosList.push({ usuario, tipo, severidad, detalle });
    return nuevo;
  };
  const internal = await internalDomains();
  const reglas = await scanAudit(RANGE[range], internal, track);

  let revisados = 0;
  if (graphConfigured()) {
    // IOCs para el cruce
    const iocDomains = new Set<string>(); const iocUrls = new Set<string>(); const iocHashes = new Set<string>();
    const iocs = await query<{ ioc_type: string; value: string; source: string }>("SELECT ioc_type, value, source FROM iocs WHERE enabled = TRUE AND ioc_type IN ('domain','url','md5','sha1','sha256')").catch(() => [] as { ioc_type: string; value: string; source: string }[]);
    for (const i of iocs) {
      // Los IOC de DOMINIO derivados de feeds de URL (URLhaus/ThreatFox) generan falsos
      // positivos con newsletters: el dominio en sí suele ser benigno. Solo se usan
      // dominios de fuentes curadas (OTX/MISP/STIX/manual). Los IOC de URL exactos sí.
      if (i.ioc_type === 'domain') { if (/urlhaus|threatfox/i.test(i.source)) continue; iocDomains.add(i.value.toLowerCase()); }
      else if (i.ioc_type === 'url') iocUrls.add(i.value);
      else iocHashes.add(i.value.toLowerCase());
    }
    const scope = await scanScope();
    const r = await scanMailboxes(scope, iocDomains, iocUrls, iocHashes, track);
    revisados = r.revisados;
  }
  await query("INSERT INTO bec_meta (k, v) VALUES ('last_scan', now()::text) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v").catch(() => undefined);
  return { window: range, reglas, correoRevisado: revisados, hallazgos: nuevosList.length, nuevos: nuevosList.length, nuevosList };
}

// ---- lecturas ----
export interface BecFinding { id: string; tipo: string; usuario: string; ref: string; severidad: Sev; detalle: string; meta: unknown; estado: string; primera_vez: string; ultima_vez: string }
const SEV_ORDER = "CASE severidad WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 ELSE 2 END";

export async function getOverview(): Promise<unknown> {
  const bySev = await query<{ severidad: string; n: number }>("SELECT severidad, count(*)::int AS n FROM bec_findings WHERE estado='open' GROUP BY severidad");
  const byTipo = await query<{ tipo: string; n: number }>("SELECT tipo, count(*)::int AS n FROM bec_findings WHERE estado='open' GROUP BY tipo");
  const top = await query<BecFinding>(`SELECT id,tipo,usuario,ref,severidad,detalle,meta,estado,primera_vez,ultima_vez FROM bec_findings WHERE estado='open' ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 100`);
  const meta = await query<{ v: string }>("SELECT v FROM bec_meta WHERE k='last_scan'").catch(() => [] as { v: string }[]);
  const sev: Record<string, number> = { critica: 0, alta: 0, media: 0 };
  for (const s of bySev) sev[s.severidad] = s.n;
  const tipo: Record<string, number> = {};
  for (const t of byTipo) tipo[t.tipo] = t.n;
  return { severidad: sev, tipo, top, lastScan: meta[0]?.v ?? null };
}
export async function listFindings(opts: { estado?: string; tipo?: string } = {}): Promise<BecFinding[]> {
  const estado = opts.estado || 'open';
  const cols = 'id,tipo,usuario,ref,severidad,detalle,meta,estado,primera_vez,ultima_vez';
  if (opts.tipo) return query<BecFinding>(`SELECT ${cols} FROM bec_findings WHERE estado=$1 AND tipo=$2 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado, opts.tipo]);
  return query<BecFinding>(`SELECT ${cols} FROM bec_findings WHERE estado=$1 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado]);
}
export async function setStatus(id: string, estado: string): Promise<void> {
  if (!['open', 'resolved', 'dismissed'].includes(estado)) throw new HttpError(400, 'Estado inválido');
  await query('UPDATE bec_findings SET estado=$2, ultima_vez=now() WHERE id=$1', [id, estado]);
}

// ---- Telegram con explicación + remediación ----
const EXPLAIN: Record<string, { que: string; como: string[] }> = {
  forwarding_rule: { que: 'Se creó/modificó una regla de correo que reenvía, redirige u oculta mensajes — la técnica de persistencia más común tras un compromiso de cuenta (BEC), para robar respuestas o esconder el fraude.', como: ['Revisar y eliminar la regla si no es legítima (Exchange / OWA del usuario).', 'Forzar cambio de contraseña y revocar sesiones del buzón afectado.', 'Confirmar con la persona si creó la regla; auditar reenvíos a dominios externos en todo el tenant.'] },
  mailbox_forwarding: { que: 'El buzón tiene reenvío automático hacia otra dirección (a menudo externa). Es una forma silenciosa de exfiltrar toda la correspondencia.', como: ['Quitar el reenvío (Set-Mailbox -ForwardingSmtpAddress $null) si no es autorizado.', 'Cambiar contraseña + revocar sesiones.', 'Deshabilitar el auto-forward externo a nivel de política de Exchange.'] },
  mail_bad_url: { que: 'Un correo recibido contiene un enlace que coincide con un indicador malicioso conocido (phishing/malware).', como: ['Avisar al destinatario que NO haga clic; eliminar el correo del buzón.', 'Bloquear el dominio/URL en el firewall/proxy.', 'Si ya hizo clic: revisar el equipo y credenciales de esa persona.'] },
  mail_bad_attachment: { que: 'Un correo trae un adjunto malicioso (hash conocido) o de un tipo peligroso (ejecutable/script/HTML) usado para entregar malware.', como: ['No abrir el adjunto; eliminar el correo.', 'Si el hash es IOC: buscar el archivo en los endpoints (Velociraptor) y contener.', 'Reforzar el bloqueo de tipos de adjunto peligrosos en Exchange.'] },
};
const TIPO_TXT: Record<string, string> = { forwarding_rule: 'Regla de reenvío/ocultamiento', mailbox_forwarding: 'Reenvío de buzón', mail_bad_url: 'URL maliciosa en correo', mail_bad_attachment: 'Adjunto malicioso' };

export interface BecLike { usuario: string; tipo: string; severidad: string; detalle: string }
export function buildTelegramReport(items: BecLike[]): string {
  const L: string[] = ['📧 Agentico · Correo — señales de BEC (Business Email Compromise)', ''];
  L.push(`Detecté ${items.length} señal(es) en el correo que conviene revisar:`, '');
  items.slice(0, 15).forEach((f, i) => {
    const ex = EXPLAIN[f.tipo];
    L.push(`${i + 1}) [${String(f.severidad).toUpperCase()}] ${TIPO_TXT[f.tipo] ?? f.tipo} · ${f.usuario}`);
    L.push(`   ${f.detalle}`);
    if (ex) { L.push(`   📖 Qué es: ${ex.que}`); L.push('   🛠️ Remediación:'); ex.como.forEach((c) => L.push(`      • ${c}`)); }
    L.push('');
  });
  L.push('Quedo atento para apoyar en la contención. (Detección de solo lectura — no se tocó ningún correo.)');
  return L.join('\n');
}

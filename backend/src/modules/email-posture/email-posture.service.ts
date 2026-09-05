/**
 * Postura de correo — autenticación de dominios (SPF / DKIM / DMARC / MX).
 *
 * A diferencia de los demás módulos (que leen los logs de Wazuh), esto vive en
 * el DNS del dominio: consulta los registros en vivo, los califica con semáforo
 * y entrega el registro exacto a corregir. Además, si el tenant lo habilita,
 * lee los reportes agregados DMARC (rua) desde un buzón M365 vía Microsoft Graph
 * para ver quién está enviando "en nombre de" el dominio (suplantación).
 */
import { promises as dns } from 'dns';
import zlib from 'zlib';
import axios from 'axios';
import { env } from '../../config/env';

// ───────────────────────── Tipos ─────────────────────────
export type Grade = 'ok' | 'warn' | 'fail' | 'missing';
export interface Fix { title: string; record?: string; where: string }
export interface Check {
  key: 'spf' | 'dkim' | 'dmarc' | 'mx';
  label: string;
  grade: Grade;
  value: string | null;
  summary: string;
  findings: string[];
  fix?: Fix;
}
export interface DomainPosture {
  domain: string;
  score: number;         // 0-100
  grade: Grade;          // peor dimensión relevante
  checks: Check[];
  generatedAt: string;
}

const GRADE_FACTOR: Record<Grade, number> = { ok: 1, warn: 0.5, fail: 0, missing: 0 };

// Dominios que gestiona el cliente (configurable por env; default = el del tenant).
export function configuredDomains(): string[] {
  const raw = process.env.EMAIL_POSTURE_DOMAINS || 'gvm.com.co';
  return raw.split(',').map((d) => d.trim().toLowerCase()).filter(Boolean);
}

// Proveedores de hosting compartido cuyo include en SPF es superficie de suplantación.
const SHARED_HOSTING_RE = /(dimenoc|hostgator|secureserver|godaddy|bluehost|namecheap|hostinger|siteground|ionos|1and1|dreamhost|inmotion|a2hosting)\./i;

async function txt(name: string): Promise<string[]> {
  try { return (await dns.resolveTxt(name)).map((chunks) => chunks.join('')); }
  catch { return []; }
}

// ───────────────────────── SPF ─────────────────────────
function checkSpf(records: string[], domain: string): Check {
  const spf = records.filter((r) => /^v=spf1/i.test(r.trim()));
  const base: Check = { key: 'spf', label: 'SPF', grade: 'missing', value: null, summary: '', findings: [] };
  if (spf.length === 0) {
    return { ...base, grade: 'fail', summary: 'Sin registro SPF: cualquiera puede enviar correo con tu dominio en el remitente.',
      findings: ['No existe un TXT `v=spf1` en la raíz del dominio.'],
      fix: { title: 'Publicar un SPF que autorice solo a Microsoft 365', where: `TXT en la raíz de ${domain}`, record: 'v=spf1 include:spf.protection.outlook.com -all' } };
  }
  if (spf.length > 1) {
    return { ...base, grade: 'fail', value: spf.join(' | '), summary: 'Hay más de un registro SPF: es inválido y los receptores lo ignoran (permerror).',
      findings: [`Se encontraron ${spf.length} registros SPF; debe existir exactamente uno.`],
      fix: { title: 'Fusionar en un único registro SPF', where: `TXT en la raíz de ${domain}` } };
  }
  const rec = spf[0];
  const findings: string[] = [];
  let grade: Grade = 'ok';
  const all = /([~\-?+])all\b/i.exec(rec);
  if (!all) { grade = 'warn'; findings.push('No termina en un mecanismo `all`: la política queda indefinida.'); }
  else if (all[1] === '-') findings.push('Termina en `-all` (hardfail): estricto, lo correcto.');
  else if (all[1] === '~') { grade = 'warn'; findings.push('Termina en `~all` (softfail): el correo no autorizado se marca, no se rechaza. Endurecer a `-all` cuando estés seguro.'); }
  else { grade = 'fail'; findings.push(`Termina en \`${all[1]}all\`: permite (o es neutral con) remitentes no listados — anula el propósito del SPF.`); }

  // Cuenta de lookups DNS (límite 10; pasarse causa permerror).
  const lookups = (rec.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
  if (lookups > 10) { grade = grade === 'ok' ? 'warn' : grade; findings.push(`~${lookups} búsquedas DNS (límite 10): riesgo de permerror. Reducir includes.`); }

  const shared = (rec.match(/include:([^\s]+)/gi) || []).filter((i) => SHARED_HOSTING_RE.test(i));
  if (shared.length) { grade = grade === 'ok' ? 'warn' : grade; findings.push(`Autoriza hosting compartido (${shared.join(', ')}): todo cliente de ese proveedor puede enviar como tu dominio. Si ya migraste el correo a M365, quítalo.`); }

  if (/include:spf\.protection\.outlook\.com/i.test(rec)) findings.push('Incluye Microsoft 365 (spf.protection.outlook.com): correcto para tu tenant.');

  return { ...base, grade, value: rec, summary: grade === 'ok' ? 'SPF presente y estricto.' : 'SPF presente, con puntos a endurecer.', findings,
    fix: grade === 'ok' ? undefined : { title: 'SPF recomendado (solo M365)', where: `TXT en la raíz de ${domain}`, record: 'v=spf1 include:spf.protection.outlook.com -all' } };
}

// ───────────────────────── DMARC ─────────────────────────
function parseKv(rec: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of rec.split(';')) {
    const [k, v] = part.split('=');
    if (k && v) out[k.trim().toLowerCase()] = v.trim();
  }
  return out;
}
function checkDmarc(records: string[], domain: string): Check {
  const dm = records.filter((r) => /^v=DMARC1/i.test(r.trim()));
  const base: Check = { key: 'dmarc', label: 'DMARC', grade: 'missing', value: null, summary: '', findings: [] };
  const recommended = `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; fo=1`;
  if (dm.length === 0) {
    return { ...base, grade: 'fail', summary: 'Sin DMARC: no hay política contra la suplantación ni visibilidad de quién abusa del dominio.',
      findings: ['No existe TXT en `_dmarc.' + domain + '`.'],
      fix: { title: 'Publicar DMARC en modo monitoreo (arranque seguro)', where: `TXT en _dmarc.${domain}`, record: recommended } };
  }
  const rec = dm[0];
  const kv = parseKv(rec);
  const p = (kv.p || 'none').toLowerCase();
  const findings: string[] = [];
  let grade: Grade;
  if (p === 'reject') { grade = 'ok'; findings.push('`p=reject`: se rechaza el correo que suplanta el dominio. Máxima protección.'); }
  else if (p === 'quarantine') { grade = 'warn'; findings.push('`p=quarantine`: el correo suplantado va a spam. Buen paso; la meta es `p=reject`.'); }
  else { grade = 'fail'; findings.push('`p=none`: modo monitoreo — NO protege. Cualquiera puede suplantar y el correo se entrega igual.'); }

  if (!kv.rua) { grade = grade === 'ok' ? 'warn' : grade; findings.push('Sin `rua=`: no estás recibiendo los reportes agregados; no ves quién te suplanta.'); }
  else findings.push(`Reportes agregados a: ${kv.rua.replace(/mailto:/gi, '')}.`);
  if (kv.pct && kv.pct !== '100') findings.push(`\`pct=${kv.pct}\`: la política solo aplica al ${kv.pct}% del correo.`);
  if (kv.sp) findings.push(`Política de subdominios \`sp=${kv.sp}\`.`);

  // Ruta de endurecimiento
  let fix: Fix | undefined;
  if (p === 'none') fix = { title: 'Paso 1: agregar rua y observar 2–4 semanas; luego subir a quarantine', where: `TXT en _dmarc.${domain}`, record: recommended };
  else if (p === 'quarantine') fix = { title: 'Paso final: endurecer a reject cuando los reportes estén limpios', where: `TXT en _dmarc.${domain}`, record: `v=DMARC1; p=reject; rua=mailto:dmarc@${domain}; fo=1` };
  else if (!kv.rua) fix = { title: 'Agregar rua para conservar visibilidad', where: `TXT en _dmarc.${domain}`, record: `${rec.replace(/;?\s*$/, '')}; rua=mailto:dmarc@${domain}` };

  return { ...base, grade, value: rec, summary: p === 'reject' ? 'DMARC en aplicación (reject).' : p === 'quarantine' ? 'DMARC en cuarentena — a un paso de reject.' : 'DMARC solo en monitoreo (no protege).', findings, fix };
}

// ───────────────────────── DKIM ─────────────────────────
// Los selectores DKIM son arbitrarios; probamos los más comunes (M365 + genéricos).
const DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'k1', 'k2', 'default', 's1', 's2', 'mail', 'dkim', 'mandrill', 'sig1', 'smtp'];
async function checkDkim(domain: string): Promise<Check> {
  const base: Check = { key: 'dkim', label: 'DKIM', grade: 'warn', value: null, summary: '', findings: [] };
  const found: string[] = [];
  let m365 = false;
  await Promise.all(DKIM_SELECTORS.map(async (sel) => {
    const host = `${sel}._domainkey.${domain}`;
    try {
      const cn = await dns.resolveCname(host);
      if (cn.length) { found.push(`${sel} → ${cn[0]}`); if (/dkim\.mail\.microsoft|onmicrosoft/i.test(cn[0])) m365 = true; return; }
    } catch { /* sin CNAME, probar TXT */ }
    const t = await txt(host);
    if (t.some((r) => /v=DKIM1|p=/i.test(r))) found.push(`${sel} (TXT)`);
  }));

  if (found.length === 0) {
    return { ...base, grade: 'warn', summary: 'No se detectó DKIM en los selectores comunes (puede usar uno propio).',
      findings: ['No respondió ningún selector común. Si usas otro selector, verifica en tu proveedor.'],
      fix: { title: 'Habilitar DKIM en Microsoft 365', where: 'Portal Defender → Email & collaboration → Email authentication → DKIM', record: 'CNAME selector1/selector2._domainkey → (los que da el portal M365)' } };
  }
  return { ...base, grade: 'ok', value: found.join('  |  '),
    summary: m365 ? 'DKIM configurado para Microsoft 365.' : 'DKIM configurado.',
    findings: [m365 ? 'selector1/selector2 firman con las llaves de Microsoft.' : `Selectores activos: ${found.length}.`,
      'Confirma que la FIRMA esté habilitada en el portal (los CNAME existentes solo indican que está aprovisionado).'] };
}

// ───────────────────────── MX ─────────────────────────
async function checkMx(domain: string): Promise<Check> {
  const base: Check = { key: 'mx', label: 'MX (entrada de correo)', grade: 'warn', value: null, summary: '', findings: [] };
  try {
    const mx = (await dns.resolveMx(domain)).sort((a, b) => a.priority - b.priority);
    if (mx.length === 0) throw new Error('empty');
    const val = mx.map((m) => `${m.priority} ${m.exchange}`).join(', ');
    const m365 = mx.some((m) => /mail\.protection\.outlook\.com/i.test(m.exchange));
    return { ...base, grade: 'ok', value: val, summary: m365 ? 'El correo entra por Microsoft 365.' : 'MX publicado.',
      findings: [m365 ? 'MX apunta a *.mail.protection.outlook.com (M365), consistente con el tenant.' : `Proveedor de correo: ${mx[0].exchange}.`] };
  } catch {
    return { ...base, grade: 'warn', summary: 'Sin registros MX (el dominio no recibe correo por sí mismo).', findings: ['No hay MX; normal si es un dominio solo de envío.'] };
  }
}

// ───────────────────────── Postura por dominio ─────────────────────────
export async function getDomainPosture(domain: string): Promise<DomainPosture> {
  const d = domain.trim().toLowerCase();
  const [root, dmarcTxt, dkim, mx] = await Promise.all([
    txt(d), txt(`_dmarc.${d}`), checkDkim(d), checkMx(d),
  ]);
  const checks: Check[] = [checkSpf(root, d), dkim, checkDmarc(dmarcTxt, d), mx];

  // Score ponderado: DMARC 35, SPF 30, DKIM 25, MX 10.
  const W: Record<Check['key'], number> = { dmarc: 35, spf: 30, dkim: 25, mx: 10 };
  const score = Math.round(checks.reduce((s, c) => s + W[c.key] * GRADE_FACTOR[c.grade], 0));
  const relevant = checks.filter((c) => c.key !== 'mx');
  const grade: Grade = relevant.some((c) => c.grade === 'fail' || c.grade === 'missing') ? 'fail'
    : relevant.some((c) => c.grade === 'warn') ? 'warn' : 'ok';

  return { domain: d, score, grade, checks, generatedAt: new Date().toISOString() };
}

export async function getPosture(domainsIn?: string[]): Promise<DomainPosture[]> {
  const domains = domainsIn && domainsIn.length ? domainsIn : configuredDomains();
  return Promise.all(domains.map(getDomainPosture));
}

// ═════════════════════ Parte B: reportes DMARC (rua) vía Graph ═════════════════════
export interface DmarcReadiness {
  ready: boolean;
  graphConfigured: boolean;
  mailReadScope: boolean;
  mailbox: string | null;
  missing: { step: string; detail: string }[];
}
export interface DmarcSource { ip: string; count: number; pass: number; fail: number; disposition: string }
export interface DmarcReportSummary {
  ready: boolean;
  readiness: DmarcReadiness;
  reports: number;
  totalMessages: number;
  aligned: number;
  failing: number;
  passRate: number;         // 0-100
  sources: DmarcSource[];   // suplantadores (fail) primero
  reporters: { name: string; count: number }[];
  window: { from: string; to: string } | null;
  generatedAt: string;
}

let graphTok: { token: string; exp: number } | null = null;
async function graphToken(): Promise<string> {
  if (graphTok && Date.now() < graphTok.exp) return graphTok.token;
  const body = new URLSearchParams({
    client_id: env.GRAPH_CLIENT_ID || '', client_secret: env.GRAPH_CLIENT_SECRET || '',
    scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
  });
  const { data } = await axios.post<{ access_token: string; expires_in: number }>(
    `https://login.microsoftonline.com/${env.GRAPH_TENANT_ID}/oauth2/v2.0/token`, body.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  graphTok = { token: data.access_token, exp: Date.now() + (data.expires_in - 60) * 1000 };
  return data.access_token;
}
function tokenRoles(token: string): string[] {
  try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString()).roles || []; }
  catch { return []; }
}

export async function dmarcReadiness(): Promise<DmarcReadiness> {
  const graphConfigured = Boolean(env.GRAPH_TENANT_ID && env.GRAPH_CLIENT_ID && env.GRAPH_CLIENT_SECRET);
  const mailbox = process.env.EMAIL_DMARC_MAILBOX || null;
  let mailReadScope = false;
  if (graphConfigured) {
    try { const roles = tokenRoles(await graphToken()); mailReadScope = roles.some((r) => /^Mail\.Read(Write)?(\.All)?$/i.test(r) || /^Mail\.Read/i.test(r)); }
    catch { mailReadScope = false; }
  }
  const missing: { step: string; detail: string }[] = [];
  if (!graphConfigured) missing.push({ step: 'Configurar Microsoft Graph', detail: 'Definir GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET.' });
  if (graphConfigured && !mailReadScope) missing.push({ step: 'Conceder permiso Mail.Read a la app', detail: 'En Azure AD → App registrations → la app de HexWatch → API permissions → agregar Microsoft Graph → Application → Mail.Read → conceder consentimiento de administrador.' });
  if (!mailbox) missing.push({ step: 'Crear el buzón de reportes y apuntarlo', detail: 'Crear dmarc@<dominio>, definir EMAIL_DMARC_MAILBOX con esa dirección, y publicar rua=mailto:dmarc@<dominio> en el DMARC. Los reportes llegan en 1–3 días.' });
  return { ready: missing.length === 0, graphConfigured, mailReadScope, mailbox, missing };
}

/** Parser mínimo del XML agregado DMARC (esquema plano y bien conocido; sin dependencias). */
function parseDmarcXml(xml: string): { org: string; begin?: number; end?: number; rows: { ip: string; count: number; disp: string; dkim: string; spf: string }[] } {
  const grab = (re: RegExp, s: string) => (re.exec(s)?.[1] || '').trim();
  const org = grab(/<org_name>([\s\S]*?)<\/org_name>/i, xml) || 'desconocido';
  const begin = Number(grab(/<begin>(\d+)<\/begin>/i, xml)) || undefined;
  const end = Number(grab(/<end>(\d+)<\/end>/i, xml)) || undefined;
  const rows: { ip: string; count: number; disp: string; dkim: string; spf: string }[] = [];
  for (const rec of xml.match(/<record>[\s\S]*?<\/record>/gi) || []) {
    const pe = /<policy_evaluated>([\s\S]*?)<\/policy_evaluated>/i.exec(rec)?.[1] || '';
    rows.push({
      ip: grab(/<source_ip>([\s\S]*?)<\/source_ip>/i, rec),
      count: Number(grab(/<count>(\d+)<\/count>/i, rec)) || 0,
      disp: grab(/<disposition>([\s\S]*?)<\/disposition>/i, pe) || 'none',
      dkim: grab(/<dkim>([\s\S]*?)<\/dkim>/i, pe).toLowerCase(),
      spf: grab(/<spf>([\s\S]*?)<\/spf>/i, pe).toLowerCase(),
    });
  }
  return { org, begin, end, rows };
}

function decodeAttachment(name: string, contentType: string, b64: string): string | null {
  const buf = Buffer.from(b64, 'base64');
  const isGz = /gzip/i.test(contentType) || /\.gz$/i.test(name);
  const isZip = /zip/i.test(contentType) || /\.zip$/i.test(name);
  try {
    if (isGz) return zlib.gunzipSync(buf).toString('utf8');
    if (isZip) return null; // ZIP requeriría una librería; los reportes .gz (Google/MS/Yahoo) sí se cubren.
    if (/xml/i.test(contentType) || /\.xml$/i.test(name) || buf.slice(0, 5).toString() === '<?xml') return buf.toString('utf8');
  } catch { /* adjunto corrupto */ }
  return null;
}

interface GraphAttachment { name?: string; contentType?: string; contentBytes?: string }
interface GraphMessage { id: string; hasAttachments?: boolean; from?: { emailAddress?: { address?: string } } }

export async function getDmarcReports(days = 14): Promise<DmarcReportSummary> {
  const readiness = await dmarcReadiness();
  const empty: DmarcReportSummary = { ready: false, readiness, reports: 0, totalMessages: 0, aligned: 0, failing: 0, passRate: 0, sources: [], reporters: [], window: null, generatedAt: new Date().toISOString() };
  if (!readiness.ready || !readiness.mailbox) return empty;

  const token = await graphToken();
  const h = { Authorization: `Bearer ${token}` };
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const bySource = new Map<string, DmarcSource>();
  const byReporter = new Map<string, number>();
  let reports = 0, aligned = 0, failing = 0;
  let winFrom = Infinity, winTo = 0;

  // Lista mensajes con adjuntos en la ventana.
  const listUrl = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(readiness.mailbox)}/messages`
    + `?$filter=receivedDateTime ge ${since} and hasAttachments eq true&$select=id,hasAttachments,from&$top=50`;
  const { data } = await axios.get<{ value: GraphMessage[] }>(listUrl, { headers: h });
  const messages = data.value || [];

  for (const msg of messages) {
    const at = await axios.get<{ value: GraphAttachment[] }>(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(readiness.mailbox)}/messages/${msg.id}/attachments`, { headers: h });
    for (const a of at.data.value || []) {
      if (!a.contentBytes) continue;
      const xml = decodeAttachment(a.name || '', a.contentType || '', a.contentBytes);
      if (!xml || !/<feedback/i.test(xml)) continue;
      const parsed = parseDmarcXml(xml);
      reports++;
      byReporter.set(parsed.org, (byReporter.get(parsed.org) || 0) + 1);
      if (parsed.begin) winFrom = Math.min(winFrom, parsed.begin);
      if (parsed.end) winTo = Math.max(winTo, parsed.end);
      for (const row of parsed.rows) {
        const passed = row.dkim === 'pass' || row.spf === 'pass'; // alineación DMARC
        if (passed) aligned += row.count; else failing += row.count;
        const cur = bySource.get(row.ip) || { ip: row.ip, count: 0, pass: 0, fail: 0, disposition: row.disp };
        cur.count += row.count; cur[passed ? 'pass' : 'fail'] += row.count;
        if (row.disp && row.disp !== 'none') cur.disposition = row.disp;
        bySource.set(row.ip, cur);
      }
    }
  }

  const total = aligned + failing;
  const sources = [...bySource.values()].sort((a, b) => (b.fail - a.fail) || (b.count - a.count)).slice(0, 30);
  const reporters = [...byReporter.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  return {
    ready: true, readiness, reports, totalMessages: messages.length,
    aligned, failing, passRate: total ? Math.round((aligned / total) * 100) : 0,
    sources, reporters,
    window: winTo ? { from: new Date(winFrom * 1000).toISOString(), to: new Date(winTo * 1000).toISOString() } : null,
    generatedAt: new Date().toISOString(),
  };
}

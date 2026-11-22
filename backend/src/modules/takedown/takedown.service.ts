/**
 * Generador de Takedown — arma el paquete de solicitud de retiro para los dominios
 * de suplantación detectados por el DRP: resuelve contactos de abuso (registrador y
 * hosting) por RDAP y redacta el correo de abuso con la evidencia.
 *
 * NO ENVÍA NADA: solo construye el borrador; el envío es una acción humana.
 * Las consultas RDAP son sobre el DOMINIO/IP MALICIOSO (público), no del cliente.
 */
import axios from 'axios';
import { logger } from '../../config/logger';
import { listFindings as drpFindings } from '../drp/drp.service';

const http = axios.create({ timeout: 20000, maxRedirects: 5, headers: { 'User-Agent': 'hexwatch-soc/1.0', Accept: 'application/rdap+json, application/json' } });

interface Vcard { [k: string]: unknown }
interface RdapEntity { roles?: string[]; vcardArray?: unknown[]; entities?: RdapEntity[] }

function vcardGet(e: RdapEntity, prop: string): string | null {
  const v = e.vcardArray;
  if (!Array.isArray(v) || v.length < 2 || !Array.isArray(v[1])) return null;
  for (const item of v[1] as unknown[][]) {
    if (Array.isArray(item) && item[0] === prop && typeof item[3] === 'string') return item[3];
  }
  return null;
}
function findByRole(ents: RdapEntity[] | undefined, role: string): RdapEntity | null {
  for (const e of ents ?? []) {
    if ((e.roles ?? []).includes(role)) return e;
    const sub = findByRole(e.entities, role);
    if (sub) return sub;
  }
  return null;
}

export interface AbuseInfo { registrar: string | null; abuseEmail: string | null }
async function rdapDomain(domain: string): Promise<AbuseInfo> {
  try {
    const { data } = await http.get<{ entities?: RdapEntity[] }>(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    const reg = findByRole(data.entities, 'registrar');
    const abuse = findByRole(data.entities, 'abuse');
    return { registrar: reg ? vcardGet(reg, 'fn') : null, abuseEmail: abuse ? vcardGet(abuse, 'email') : null };
  } catch (e) { logger.warn({ err: (e as Error).message, domain }, 'takedown: rdap domain'); return { registrar: null, abuseEmail: null }; }
}
async function rdapIp(ip: string): Promise<{ net: string | null; abuseEmail: string | null }> {
  try {
    const { data } = await http.get<{ name?: string; entities?: RdapEntity[] }>(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
    const abuse = findByRole(data.entities, 'abuse');
    return { net: data.name ?? null, abuseEmail: abuse ? vcardGet(abuse, 'email') : null };
  } catch (e) { logger.warn({ err: (e as Error).message, ip }, 'takedown: rdap ip'); return { net: null, abuseEmail: null }; }
}

interface DrpMeta { mx?: boolean; ips?: string[]; brand?: string; tecnica?: string }
export interface Candidate { id: string; domain: string; brand: string; tecnica: string; mx: boolean; ips: string[]; severidad: string; primeraVez: string; ultimaVez: string; detalle: string }

export async function getCandidates(): Promise<Candidate[]> {
  const fs = await drpFindings({ estado: 'open' });
  return fs
    .filter((f) => f.tipo === 'lookalike_domain' || f.tipo === 'lookalike_cert')
    .map((f) => {
      const m = (f.meta ?? {}) as DrpMeta;
      return {
        id: f.id, domain: f.dominio, brand: f.brand, tecnica: m.tecnica ?? f.tipo,
        mx: !!m.mx, ips: Array.isArray(m.ips) ? m.ips : [],
        severidad: f.severidad, primeraVez: f.primera_vez, ultimaVez: f.ultima_vez, detalle: f.detalle,
      };
    });
}

export interface TakedownRecipient { tipo: string; email: string }
export interface TakedownPackage {
  domain: string; brand: string; registrar: string | null; hosting: string | null;
  recipients: TakedownRecipient[]; subject: string; body: string;
  evidence: { tecnica: string; mx: boolean; ips: string[]; primeraVez: string | null; ultimaVez: string | null };
  aviso: string;
}

export async function generatePackage(domainIn: string): Promise<TakedownPackage> {
  const domain = domainIn.trim().toLowerCase();
  const cand = (await getCandidates()).find((c) => c.domain.toLowerCase() === domain);
  const brand = cand?.brand ?? '';
  const ips = cand?.ips ?? [];
  const mx = cand?.mx ?? false;

  const dom = await rdapDomain(domain);
  const ipInfo = ips.length ? await rdapIp(ips[0]) : { net: null, abuseEmail: null };

  const recipients: TakedownRecipient[] = [];
  const seen = new Set<string>();
  const add = (tipo: string, email: string | null) => { if (email && !seen.has(email.toLowerCase())) { seen.add(email.toLowerCase()); recipients.push({ tipo, email }); } };
  add(`Registrador${dom.registrar ? ` (${dom.registrar})` : ''}`, dom.abuseEmail);
  add(`Hosting${ipInfo.net ? ` (${ipInfo.net})` : ''}`, ipInfo.abuseEmail);

  const subject = `Abuse report / takedown request: ${domain} impersonating ${brand || 'our client'}`;
  const body = [
    `To whom it may concern,`,
    ``,
    `We report the domain "${domain}" for brand impersonation and potential phishing targeting our client${brand ? ` (${brand})` : ''}.`,
    ``,
    `Findings:`,
    `- Look-alike domain: ${domain}${cand ? ` (technique: ${cand.tecnica})` : ''}`,
    `- Impersonated brand/domain: ${brand || '(client brand)'}`,
    ips.length ? `- Hosting IP(s): ${ips.join(', ')}${ipInfo.net ? ` (${ipInfo.net})` : ''}` : `- Hosting IP(s): not resolved`,
    `- Mail exchanger (MX) configured: ${mx ? 'YES — the domain can send/receive email, enabling email spoofing and phishing against the brand.' : 'no'}`,
    cand ? `- First observed: ${new Date(cand.primeraVez).toISOString().slice(0, 10)} · Last observed: ${new Date(cand.ultimaVez).toISOString().slice(0, 10)}` : '',
    ``,
    `This domain closely mimics our client's legitimate domain and poses a risk of phishing and fraud against their customers and staff. We respectfully request the suspension/takedown of the domain and any associated services under your abuse / acceptable-use policy.`,
    ``,
    `Further evidence (screenshots, DNS/TLS records) is available upon request.`,
    ``,
    `Regards,`,
    `Security Operations Center (SOC)`,
  ].filter((l) => l !== '').join('\n');

  return {
    domain, brand, registrar: dom.registrar, hosting: ipInfo.net,
    recipients, subject, body,
    evidence: { tecnica: cand?.tecnica ?? '', mx, ips, primeraVez: cand?.primeraVez ?? null, ultimaVez: cand?.ultimaVez ?? null },
    aviso: recipients.length
      ? 'HexWatch arma el paquete; NO lo envía. Verifica los datos y envíalo desde tu correo de abuso del SOC. Para dominios .co o casos en Colombia puedes notificar también a colCERT.'
      : 'No se encontró contacto de abuso por RDAP (puede estar protegido por privacidad). Consulta el WHOIS del registrador manualmente. HexWatch no envía nada.',
  };
}

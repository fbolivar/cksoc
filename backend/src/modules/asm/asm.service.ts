/**
 * ASM — Attack Surface Management externo.
 * Descubre y vigila la superficie expuesta a Internet de los dominios
 * AUTORIZADOS del cliente (los que estén en asm_domains):
 *   1) Descubrimiento de subdominios por Certificate Transparency (crt.sh).
 *   2) Resolución DNS -> IPs públicas.
 *   3) Escaneo TCP-connect de un set acotado de puertos sensibles.
 *   4) Inspección de certificado TLS (emisor, vigencia, autofirmado).
 *   5) Cruce de IPs con IOCs conocidos.
 * Genera hallazgos (asm_findings) priorizados por severidad. Es escaneo ACTIVO
 * limitado a los dominios propios del cliente (autorizado). Guardrails:
 * concurrencia y timeouts acotados, sólo IPs públicas, tope de subdominios.
 */
import { promises as dns } from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';
import { isPublicIP } from '../geo/geoip.service';

const UA = 'HexWatch-SOC/1.0 (asm)';
type Sev = 'critica' | 'alta' | 'media' | 'baja' | 'info';

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5601, 5900, 5985, 6379, 8000, 8080, 8443, 9000, 9200, 9300, 10000, 11211, 27017];
const SEV_ORDER = "CASE severidad WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 WHEN 'media' THEN 2 WHEN 'baja' THEN 3 ELSE 4 END";

function cfgPorts(): number[] {
  const raw = (env.ASM_PORTS || '').trim();
  if (!raw) return DEFAULT_PORTS;
  const list = raw.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => n > 0 && n < 65536);
  return list.length ? list : DEFAULT_PORTS;
}
const TIMEOUT = Number(env.ASM_CONNECT_TIMEOUT_MS) || 2500;
const CONC = Number(env.ASM_MAX_CONCURRENCY) || 40;
const TLS_WARN = Number(env.ASM_TLS_EXPIRY_WARN_DAYS) || 21;
const MAX_SUBDOMAINS = 800;

export function isAsmEnabled(): boolean {
  return String(env.ASM_ENABLED ?? 'true').toLowerCase() !== 'false';
}

const PORT_SEV: Record<number, Sev> = {
  23: 'critica', 445: 'critica', 3389: 'critica', 3306: 'critica', 5432: 'critica', 6379: 'critica',
  27017: 'critica', 9200: 'critica', 1433: 'critica', 1521: 'critica', 11211: 'critica', 2375: 'critica',
  5900: 'critica', 5985: 'critica', 2049: 'critica',
  21: 'alta', 22: 'alta', 161: 'alta', 135: 'alta', 139: 'alta', 389: 'alta', 10000: 'alta', 5601: 'alta', 9300: 'alta',
  3000: 'media', 9000: 'media', 8000: 'media', 110: 'media', 143: 'media', 25: 'media', 53: 'media', 8080: 'media', 8443: 'media',
  587: 'baja', 465: 'baja', 993: 'info', 995: 'info', 80: 'info', 443: 'info',
};
const PORT_NAME: Record<number, string> = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 2375: 'Docker', 3000: 'App', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5601: 'Kibana', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 8000: 'HTTP-alt', 8080: 'HTTP-proxy', 8443: 'HTTPS-alt', 9000: 'App', 9200: 'Elasticsearch', 9300: 'Elastic', 10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB' };
function portSev(p: number): Sev { return PORT_SEV[p] ?? 'media'; }
function portLabel(p: number): string { return PORT_NAME[p] || String(p); }

export interface AsmFinding {
  id: string; domain: string; host: string; ip: string | null; tipo: string;
  puerto: number; severidad: Sev; detalle: string; estado: string;
  primera_vez: string; ultima_vez: string;
}
interface AsmNew { host: string; severidad: Sev; detalle: string; }

// --- Descubrimiento por Certificate Transparency (crt.sh) ---
async function discoverSubdomains(domain: string): Promise<string[]> {
  const url = 'https://crt.sh/?q=' + encodeURIComponent('%.' + domain) + '&output=json';
  const set = new Set<string>([domain]);
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    const r = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/json' }, signal: ctrl.signal });
    clearTimeout(t);
    if (r.ok) {
      const rows = (await r.json()) as Array<{ name_value?: string; common_name?: string }>;
      for (const row of rows) {
        const names = String(row.name_value || '').split('\n').concat(String(row.common_name || ''));
        for (let n of names) {
          n = n.trim().toLowerCase().replace(/^\*\./, '');
          if (n && (n === domain || n.endsWith('.' + domain)) && !n.includes(' ') && !n.includes('@')) set.add(n);
        }
      }
    }
  } catch (e) {
    logger.warn({ err: e instanceof Error ? e.message : e, domain }, 'ASM: crt.sh falló');
  }
  return [...set].slice(0, MAX_SUBDOMAINS);
}

async function resolveHost(host: string): Promise<string[]> {
  const ips = new Set<string>();
  try { for (const a of await dns.resolve4(host)) ips.add(a); } catch { /* sin A */ }
  try { for (const a of await dns.resolve6(host)) ips.add(a); } catch { /* sin AAAA */ }
  return [...ips];
}

function tcpOpen(ip: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open: boolean): void => { if (done) return; done = true; sock.destroy(); resolve(open); };
    sock.setTimeout(TIMEOUT);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    try { sock.connect(port, ip); } catch { finish(false); }
  });
}

interface TlsInfo { issuer: string; daysToExpiry: number; selfSigned: boolean; validTo: string; }
function inspectTls(ip: string, port: number, servername: string): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    let done = false;
    const fin = (v: TlsInfo | null): void => { if (done) return; done = true; try { sock.destroy(); } catch { /* noop */ } resolve(v); };
    const sock = tls.connect({ host: ip, port, servername, rejectUnauthorized: false, timeout: TIMEOUT }, () => {
      const c = sock.getPeerCertificate();
      if (!c || !c.valid_to) { fin(null); return; }
      const issuer = c.issuer as { O?: string; CN?: string } | undefined;
      const subject = c.subject as { O?: string; CN?: string } | undefined;
      const validTo = new Date(c.valid_to);
      const days = Math.round((validTo.getTime() - Date.now()) / 86400000);
      const selfSigned = !!(issuer && subject && issuer.CN === subject.CN && (issuer.O || '') === (subject.O || ''));
      fin({ issuer: String(issuer?.O || issuer?.CN || 'desconocido'), daysToExpiry: days, selfSigned, validTo: validTo.toISOString().slice(0, 10) });
    });
    sock.once('error', () => fin(null));
    sock.once('timeout', () => fin(null));
  });
}

async function mapPool<T>(items: T[], worker: (it: T) => Promise<void>, conc: number): Promise<void> {
  let i = 0;
  const runners = Array.from({ length: Math.min(conc, items.length || 1) }, async () => {
    while (i < items.length) { const idx = i++; await worker(items[idx]); }
  });
  await Promise.all(runners);
}

async function isIoc(ip: string): Promise<boolean> {
  try {
    const rows = await query<{ n: number }>("SELECT count(*)::int AS n FROM iocs WHERE ioc_type='ip' AND value=$1 AND enabled", [ip]);
    return (rows[0]?.n ?? 0) > 0;
  } catch { return false; }
}

async function upsertAsset(domain: string, host: string, ip: string): Promise<void> {
  await query(
    `INSERT INTO asm_assets (domain, host, ip, fuente, activo, ultima_vez)
       VALUES ($1,$2,$3,'ct',true, now())
     ON CONFLICT (host, ip) DO UPDATE SET activo=true, ultima_vez=now(), domain=EXCLUDED.domain`,
    [domain, host, ip],
  );
}

async function addFinding(f: { domain: string; host: string; ip: string | null; tipo: string; puerto: number; severidad: Sev; detalle: string }): Promise<boolean> {
  const rows = await query<{ nuevo: boolean }>(
    `INSERT INTO asm_findings (domain,host,ip,tipo,puerto,severidad,detalle,estado,ultima_vez)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'open', now())
     ON CONFLICT (host, tipo, puerto) DO UPDATE
       SET ip=EXCLUDED.ip, severidad=EXCLUDED.severidad, detalle=EXCLUDED.detalle, ultima_vez=now(),
           estado = CASE WHEN asm_findings.estado='dismissed' THEN 'dismissed' ELSE 'open' END
     RETURNING (xmax = 0) AS nuevo`,
    [f.domain, f.host, f.ip, f.tipo, f.puerto, f.severidad, f.detalle],
  );
  return rows[0]?.nuevo ?? false;
}

export interface ScanResult { domain: string; hosts: number; assets: number; openPorts: number; nuevos: number; nuevosList: AsmNew[] }

export async function scanDomain(domainIn: string): Promise<ScanResult> {
  const domain = domainIn.trim().toLowerCase();
  const nuevosList: AsmNew[] = [];
  const track = async (host: string, sev: Sev, detalle: string, tipo: string, puerto: number, ip: string | null): Promise<void> => {
    if (await addFinding({ domain, host, ip, tipo, puerto, severidad: sev, detalle })) nuevosList.push({ host, severidad: sev, detalle });
  };
  try {
    const hosts = await discoverSubdomains(domain);
    const ports = cfgPorts();
    let assetCount = 0, openPorts = 0;
    for (const host of hosts) {
      const ips = await resolveHost(host);
      const pub = ips.filter((ip) => isPublicIP(ip));
      if (ips.length && !pub.length) {
        await track(host, 'baja', `Registro DNS público apunta a IP privada ${ips[0]} (posible fuga de topología interna)`, 'private_dns', 0, ips[0]);
        continue;
      }
      for (const ip of pub) {
        await upsertAsset(domain, host, ip); assetCount++;
        if (await isIoc(ip)) await track(host, 'critica', `La IP ${ip} de ${host} figura en un IOC conocido (reputación maliciosa)`, 'ioc_match', 0, ip);
        const open: number[] = [];
        await mapPool(ports, async (p) => { if (await tcpOpen(ip, p)) open.push(p); }, CONC);
        for (const p of open) {
          openPorts++;
          const sev = portSev(p);
          if (sev !== 'info') await track(host, sev, `Puerto ${p}/${portLabel(p)} expuesto a Internet en ${ip}`, 'open_port', p, ip);
          if (p === 443 || p === 8443) {
            const info = await inspectTls(ip, p, host);
            if (info) {
              if (info.daysToExpiry < 0) await track(host, 'alta', `Certificado TLS VENCIDO (${info.validTo}) en ${host}:${p} — emisor ${info.issuer}`, 'tls_expired', p, ip);
              else if (info.daysToExpiry <= TLS_WARN) await track(host, 'media', `Certificado TLS vence en ${info.daysToExpiry} días (${info.validTo}) en ${host}:${p}`, 'tls_expiring', p, ip);
              if (info.selfSigned) await track(host, 'media', `Certificado TLS autofirmado en ${host}:${p} (emisor ${info.issuer})`, 'tls_selfsigned', p, ip);
            }
          }
        }
      }
    }
    await query('UPDATE asm_domains SET ultimo_scan=now(), ultimo_error=NULL WHERE domain=$1', [domain]).catch(() => undefined);
    return { domain, hosts: hosts.length, assets: assetCount, openPorts, nuevos: nuevosList.length, nuevosList };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await query('UPDATE asm_domains SET ultimo_scan=now(), ultimo_error=$2 WHERE domain=$1', [domain, msg]).catch(() => undefined);
    throw e instanceof HttpError ? e : new HttpError(500, `Escaneo ASM falló: ${msg}`);
  }
}

export async function scanAll(): Promise<ScanResult[]> {
  const doms = await query<{ domain: string }>('SELECT domain FROM asm_domains WHERE habilitado = true ORDER BY domain');
  const out: ScanResult[] = [];
  for (const d of doms) {
    try { out.push(await scanDomain(d.domain)); }
    catch (e) { logger.error({ err: e instanceof Error ? e.message : e, domain: d.domain }, 'ASM: scan de dominio falló'); }
  }
  return out;
}

// --- Gestión de dominios / consultas ---
export async function listDomains(): Promise<unknown[]> {
  return query(
    `SELECT d.domain, d.habilitado, d.ultimo_scan, d.ultimo_error,
       (SELECT count(*)::int FROM asm_assets a WHERE a.domain=d.domain AND a.activo) AS activos,
       (SELECT count(*)::int FROM asm_findings f WHERE f.domain=d.domain AND f.estado='open') AS hallazgos
     FROM asm_domains d ORDER BY d.domain`,
  );
}
export async function addDomain(domainIn: string): Promise<{ domain: string }> {
  const domain = (domainIn || '').trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new HttpError(400, 'Dominio inválido');
  await query('INSERT INTO asm_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING', [domain]);
  return { domain };
}
export async function removeDomain(domainIn: string): Promise<void> {
  const domain = (domainIn || '').trim().toLowerCase();
  await query('DELETE FROM asm_findings WHERE domain=$1', [domain]);
  await query('DELETE FROM asm_assets WHERE domain=$1', [domain]);
  await query('DELETE FROM asm_domains WHERE domain=$1', [domain]);
}
export async function listAssets(domain?: string): Promise<unknown[]> {
  if (domain) return query('SELECT domain,host,ip,fuente,activo,primera_vez,ultima_vez FROM asm_assets WHERE domain=$1 AND activo ORDER BY host', [domain.trim().toLowerCase()]);
  return query('SELECT domain,host,ip,fuente,activo,primera_vez,ultima_vez FROM asm_assets WHERE activo ORDER BY domain,host LIMIT 2000');
}
export async function listFindings(opts: { estado?: string; severidad?: string }): Promise<AsmFinding[]> {
  const estado = opts.estado || 'open';
  const cols = 'id,domain,host,ip,tipo,puerto,severidad,detalle,estado,primera_vez,ultima_vez';
  if (opts.severidad) {
    return query<AsmFinding>(`SELECT ${cols} FROM asm_findings WHERE estado=$1 AND severidad=$2 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado, opts.severidad]);
  }
  return query<AsmFinding>(`SELECT ${cols} FROM asm_findings WHERE estado=$1 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado]);
}
export async function setFindingStatus(id: string, estado: string): Promise<void> {
  if (!['open', 'resolved', 'dismissed'].includes(estado)) throw new HttpError(400, 'Estado inválido');
  await query('UPDATE asm_findings SET estado=$2, ultima_vez=now() WHERE id=$1', [id, estado]);
}
export async function getOverview(): Promise<unknown> {
  const dom = await query<{ n: number }>('SELECT count(*)::int AS n FROM asm_domains WHERE habilitado');
  const hosts = await query<{ n: number }>('SELECT count(DISTINCT host)::int AS n FROM asm_assets WHERE activo');
  const ips = await query<{ n: number }>('SELECT count(DISTINCT ip)::int AS n FROM asm_assets WHERE activo');
  const sev = await query<{ severidad: string; n: number }>("SELECT severidad, count(*)::int AS n FROM asm_findings WHERE estado='open' GROUP BY severidad");
  const top = await query<AsmFinding>(`SELECT id,domain,host,ip,tipo,puerto,severidad,detalle,estado,primera_vez,ultima_vez FROM asm_findings WHERE estado='open' ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 20`);
  const bySev: Record<string, number> = { critica: 0, alta: 0, media: 0, baja: 0, info: 0 };
  for (const s of sev) bySev[s.severidad] = s.n;
  return { dominios: dom[0]?.n ?? 0, hosts: hosts[0]?.n ?? 0, ips: ips[0]?.n ?? 0, hallazgos: bySev, top };
}

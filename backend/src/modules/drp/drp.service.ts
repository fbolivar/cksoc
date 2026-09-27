/**
 * DRP — Digital Risk Protection (sin credenciales del cliente):
 *   - TYPOSQUATTING: genera dominios parecidos (estilo dnstwist) al dominio del
 *     cliente y detecta los REGISTRADOS y ACTIVOS (DNS A + MX = capaz de phishing).
 *   - CERTIFICATE TRANSPARENCY: dominios lookalike que ya emitieron certificado
 *     (crt.sh) — infra de phishing/suplantación temprana.
 *   - CREDENCIALES FILTRADAS: se apoya en el módulo credexp (HIBP) ya existente.
 * Fuentes gratuitas (DNS + crt.sh); no requiere accesos del cliente.
 */
import { promises as dns } from 'node:dns';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';

const UA = 'HexWatch-SOC/1.0 (drp)';
type Sev = 'critica' | 'alta' | 'media';
const MAX_PERM = Number(env.DRP_MAX_PERMUTATIONS) || 700;
const CONC = Number(env.DRP_CONCURRENCY) || 30;
const DNS_TIMEOUT = Number(env.DRP_DNS_TIMEOUT_MS) || 3000;
const TLDS = (env.DRP_TLDS || 'com,net,org,co,io,info,online,site,xyz,app,biz,live,co.com,com.co,us,shop,store,click,link,help,support,security,vip,pro').split(',').map((s) => s.trim()).filter(Boolean);

export function isDrpEnabled(): boolean { return String(env.DRP_ENABLED ?? 'true').toLowerCase() !== 'false'; }

const HG: Record<string, string[]> = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], b: ['8'], g: ['9', 'q'], t: ['7'], z: ['2'], m: ['rn'], w: ['vv'], u: ['v'], d: ['cl'], n: ['m'], c: ['e'] };
const KB: Record<string, string> = { a: 'qwsz', b: 'vghn', c: 'xdfv', d: 'serfcx', e: 'wsdr', f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', i: 'ujko', j: 'huikmn', k: 'jiolm', l: 'kop', m: 'njk', n: 'bhjm', o: 'iklp', p: 'ol', q: 'wa', r: 'edft', s: 'awedxz', t: 'rfgy', u: 'yhji', v: 'cfgb', w: 'qase', x: 'zsdc', y: 'tghu', z: 'asx' };

/** Divide un dominio en sld + tld (soporta TLD de dos niveles comunes). */
function split(domain: string): { sld: string; tld: string } {
  const two = /(\.(com|co|net|org|gov|edu|mil)\.[a-z]{2})$/i.exec(domain);
  if (two) return { sld: domain.slice(0, domain.length - two[1].length), tld: two[1].slice(1) };
  const i = domain.lastIndexOf('.');
  return i < 0 ? { sld: domain, tld: '' } : { sld: domain.slice(0, i), tld: domain.slice(i + 1) };
}

/** Genera dominios parecidos (typosquatting) para un dominio. */
function permutations(domain: string): { d: string; tech: string }[] {
  const { sld, tld } = split(domain);
  const s = sld.toLowerCase();
  const out = new Map<string, string>();
  const add = (variant: string, tech: string, t = tld): void => {
    const cand = `${variant}.${t}`;
    if (variant && cand !== domain && /^[a-z0-9.-]+$/.test(cand) && !out.has(cand)) out.set(cand, tech);
  };
  // omisión, repetición, transposición, reemplazo adyacente, inserción, homoglifo, adición
  for (let i = 0; i < s.length; i++) {
    add(s.slice(0, i) + s.slice(i + 1), 'omision');
    add(s.slice(0, i) + s[i] + s[i] + s.slice(i + 1), 'repeticion');
    if (i < s.length - 1) add(s.slice(0, i) + s[i + 1] + s[i] + s.slice(i + 2), 'transposicion');
    for (const k of KB[s[i]] ?? '') add(s.slice(0, i) + k + s.slice(i + 1), 'reemplazo');
    for (const h of HG[s[i]] ?? []) add(s.slice(0, i) + h + s.slice(i + 1), 'homoglifo');
    for (const k of (KB[s[i]] ?? '').slice(0, 2)) add(s.slice(0, i) + s[i] + k + s.slice(i + 1), 'insercion');
  }
  for (const c of 'aeiolmns') add(s + c, 'adicion');
  // guion / sin guion / punto (subdominio)
  if (s.includes('-')) add(s.replace(/-/g, ''), 'sin-guion');
  else for (let i = 1; i < s.length; i++) add(s.slice(0, i) + '-' + s.slice(i), 'guion');
  // cambio de TLD (mismo nombre, otra extensión)
  for (const t of TLDS) if (t !== tld) add(s, 'tld-swap', t);
  return [...out.entries()].map(([d, tech]) => ({ d, tech })).slice(0, MAX_PERM);
}

function withTimeout<T>(p: Promise<T>): Promise<T> {
  return Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error('timeout')), DNS_TIMEOUT))]);
}
async function probe(host: string): Promise<{ a: string[]; mx: boolean }> {
  let a: string[] = [];
  try { a = await withTimeout(dns.resolve4(host)); } catch { /* no A */ }
  if (!a.length) { try { a = await withTimeout(dns.resolve6(host)); } catch { /* no AAAA */ } }
  if (!a.length) return { a: [], mx: false };
  let mx = false;
  try { mx = (await withTimeout(dns.resolveMx(host))).length > 0; } catch { /* no MX */ }
  return { a, mx };
}
async function mapPool<T>(items: T[], worker: (it: T) => Promise<void>, conc: number): Promise<void> {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(conc, items.length || 1) }, async () => {
    while (i < items.length) { const idx = i++; await worker(items[idx]); }
  }));
}

/** crt.sh: dominios con certificado que contienen el nombre de la marca. */
async function certLookalikes(keyword: string): Promise<Set<string>> {
  const set = new Set<string>();
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent('%' + keyword + '%')}&output=json`, { headers: { 'User-Agent': UA, Accept: 'application/json' }, signal: ctrl.signal });
    clearTimeout(t);
    if (r.ok) {
      const rows = (await r.json()) as { name_value?: string }[];
      for (const row of rows) for (let n of String(row.name_value || '').split('\n')) {
        n = n.trim().toLowerCase().replace(/^\*\./, '');
        if (n && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(n) && !n.includes(' ')) set.add(n);
      }
    }
  } catch (e) { logger.warn({ err: e instanceof Error ? e.message : e, keyword }, 'DRP: crt.sh falló'); }
  return set;
}

// --- marcas a proteger (dominios propios del cliente) ---
async function brands(): Promise<string[]> {
  const envList = (env.DRP_BRANDS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (envList.length) return envList;
  let rows = await query<{ domain: string }>('SELECT domain FROM asm_domains WHERE habilitado = true').catch(() => [] as { domain: string }[]);
  if (!rows.length) rows = await query<{ domain: string }>('SELECT domain FROM credexp_domains').catch(() => [] as { domain: string }[]);
  return rows.map((r) => r.domain.toLowerCase());
}

async function addFinding(f: { tipo: string; brand: string; dominio: string; severidad: Sev; detalle: string; meta: unknown }): Promise<boolean> {
  const rows = await query<{ nuevo: boolean }>(
    `INSERT INTO drp_findings (tipo, brand, dominio, severidad, detalle, meta, estado, ultima_vez)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,'open', now())
     ON CONFLICT (dominio, tipo) DO UPDATE
       SET brand=EXCLUDED.brand, severidad=EXCLUDED.severidad, detalle=EXCLUDED.detalle, meta=EXCLUDED.meta, ultima_vez=now(),
           estado = CASE WHEN drp_findings.estado='dismissed' THEN 'dismissed' ELSE 'open' END
     RETURNING (xmax = 0) AS nuevo`,
    [f.tipo, f.brand, f.dominio, f.severidad, f.detalle, JSON.stringify(f.meta)],
  );
  return rows[0]?.nuevo ?? false;
}

export interface DrpNew { dominio: string; tipo: string; severidad: Sev; detalle: string }
export interface DrpScan { brands: number; generados: number; registrados: number; certs: number; nuevos: number; nuevosList: DrpNew[] }

export async function scan(): Promise<DrpScan> {
  const bs = await brands();
  const owned = new Set(bs);
  const nuevosList: DrpNew[] = [];
  const track = async (tipo: string, brand: string, dominio: string, sev: Sev, detalle: string, meta: unknown): Promise<void> => {
    if (await addFinding({ tipo, brand, dominio, severidad: sev, detalle, meta })) nuevosList.push({ dominio, tipo, severidad: sev, detalle });
  };
  let generados = 0, registrados = 0, certs = 0;
  for (const brand of bs) {
    // 1) typosquatting activo
    const perms = permutations(brand);
    generados += perms.length;
    await mapPool(perms, async (p) => {
      if (owned.has(p.d)) return;
      const { a, mx } = await probe(p.d);
      if (!a.length) return;
      registrados++;
      const sev: Sev = mx ? 'alta' : 'media';
      await track('lookalike_domain', brand, p.d, sev, `Dominio parecido a ${brand} REGISTRADO y activo: ${p.d} (${p.tech})${mx ? ' — con MX, puede enviar correo suplantando' : ''}`, { brand, tecnica: p.tech, ips: a.slice(0, 3), mx });
    }, CONC);
    // 2) certificate transparency (nombre de marca sin TLD, y sin guiones)
    const { sld } = split(brand);
    const keys = [...new Set([sld, sld.replace(/-/g, '')])].filter((k) => k.length >= 4);
    const certSet = new Set<string>();
    for (const k of keys) for (const d of await certLookalikes(k)) certSet.add(d);
    for (const d of certSet) {
      if (owned.has(d) || d === brand || d.endsWith('.' + brand)) continue; // propio / subdominio propio
      certs++;
      const { mx } = await probe(d);
      const sev: Sev = mx ? 'alta' : 'media';
      await track('lookalike_cert', brand, d, sev, `Dominio con certificado TLS que imita a ${brand}: ${d}${mx ? ' — con MX' : ''}`, { brand, mx });
    }
  }
  await query("INSERT INTO drp_meta (k,v) VALUES ('last_scan', now()::text) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v").catch(() => undefined);
  return { brands: bs.length, generados, registrados, certs, nuevos: nuevosList.length, nuevosList };
}

// --- lecturas ---
export interface DrpFinding { id: string; tipo: string; brand: string; dominio: string; severidad: Sev; detalle: string; meta: unknown; estado: string; primera_vez: string; ultima_vez: string }
const SEV_ORDER = "CASE severidad WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 ELSE 2 END";

export async function getOverview(): Promise<unknown> {
  const bySev = await query<{ severidad: string; n: number }>("SELECT severidad, count(*)::int AS n FROM drp_findings WHERE estado='open' GROUP BY severidad");
  const byTipo = await query<{ tipo: string; n: number }>("SELECT tipo, count(*)::int AS n FROM drp_findings WHERE estado='open' GROUP BY tipo");
  const conMx = await query<{ n: number }>("SELECT count(*)::int AS n FROM drp_findings WHERE estado='open' AND (meta->>'mx')='true'");
  const top = await query<DrpFinding>(`SELECT id,tipo,brand,dominio,severidad,detalle,meta,estado,primera_vez,ultima_vez FROM drp_findings WHERE estado='open' ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 200`);
  const meta = await query<{ v: string }>("SELECT v FROM drp_meta WHERE k='last_scan'").catch(() => [] as { v: string }[]);
  const creds = await query<{ n: number }>("SELECT count(*)::int AS n FROM credexp_accounts WHERE estado <> 'dismissed'").catch(() => [{ n: 0 }]);
  const sev: Record<string, number> = { critica: 0, alta: 0, media: 0 };
  for (const s of bySev) sev[s.severidad] = s.n;
  const tipo: Record<string, number> = {};
  for (const t of byTipo) tipo[t.tipo] = t.n;
  return { severidad: sev, tipo, conMx: conMx[0]?.n ?? 0, credencialesExpuestas: creds[0]?.n ?? 0, top, lastScan: meta[0]?.v ?? null };
}
export async function listFindings(opts: { estado?: string; tipo?: string } = {}): Promise<DrpFinding[]> {
  const estado = opts.estado || 'open';
  const cols = 'id,tipo,brand,dominio,severidad,detalle,meta,estado,primera_vez,ultima_vez';
  if (opts.tipo) return query<DrpFinding>(`SELECT ${cols} FROM drp_findings WHERE estado=$1 AND tipo=$2 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado, opts.tipo]);
  return query<DrpFinding>(`SELECT ${cols} FROM drp_findings WHERE estado=$1 ORDER BY ${SEV_ORDER}, ultima_vez DESC LIMIT 1000`, [estado]);
}
export async function setStatus(id: string, estado: string): Promise<void> {
  if (!['open', 'resolved', 'dismissed'].includes(estado)) throw new HttpError(400, 'Estado inválido');
  await query('UPDATE drp_findings SET estado=$2, ultima_vez=now() WHERE id=$1', [id, estado]);
}

/**
 * Monitoreo de exposicion de credenciales (Have I Been Pwned - Domain Search).
 *
 * Vigila uno o varios dominios del cliente. Para cada dominio consulta la API
 * de HIBP "breacheddomain", que devuelve las cuentas (@dominio) que aparecen en
 * brechas conocidas junto con los nombres de las brechas. Persistimos las
 * cuentas expuestas, marcamos las NUEVAS respecto al ultimo escaneo y
 * mantenemos un catalogo local de brechas para enriquecer la vista.
 *
 * Requisitos para operar en real:
 *   - HIBP_API_KEY (suscripcion de HIBP)
 *   - propiedad del dominio verificada en el panel de HIBP
 * Sin la clave, el modulo funciona en modo "no configurado": la UI lo indica y
 * no se hacen llamadas externas.
 */
import { request } from 'node:https';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';

const HIBP_HOST = 'haveibeenpwned.com';
const UA = 'HexWatch-SOC/1.0 (credential-exposure)';

export interface CredDomain {
  domain: string;
  habilitado: boolean;
  verificado: boolean;
  ultimo_scan: string | null;
  ultimo_error: string | null;
  expuestas?: number;
}
export interface CredAccount {
  id: string;
  domain: string;
  alias: string;
  brechas: string[];
  num_brechas: number;
  estado: 'open' | 'ack' | 'dismissed';
  primera_vez: string;
  ultima_vez: string;
}
export interface BreachMeta {
  name: string;
  title: string | null;
  breach_date: string | null;
  pwn_count: number | null;
  data_classes: string[];
  is_sensitive: boolean;
}

export function isHibpConfigured(): boolean {
  return Boolean(env.HIBP_API_KEY && env.HIBP_API_KEY.trim());
}

// --------------------------------------------------------------------------
// Cliente HIBP (GET autenticado, con reintento ante 429)
// --------------------------------------------------------------------------

function hibpGet<T>(path: string): Promise<{ status: number; body: T | null; raw: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: HIBP_HOST,
        path,
        method: 'GET',
        headers: {
          'hibp-api-key': env.HIBP_API_KEY ?? '',
          'user-agent': UA,
          accept: 'application/json',
        },
        timeout: 20_000,
      },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => {
          let body: T | null = null;
          try { body = d ? (JSON.parse(d) as T) : null; } catch { body = null; }
          resolve({ status: res.statusCode ?? 0, body, raw: d });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout HIBP')));
    req.on('error', reject);
    req.end();
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --------------------------------------------------------------------------
// Dominios
// --------------------------------------------------------------------------

export async function listDomains(): Promise<CredDomain[]> {
  return query<CredDomain>(
    `SELECT d.domain, d.habilitado, d.verificado,
            to_char(d.ultimo_scan,'YYYY-MM-DD"T"HH24:MI:SSOF') AS ultimo_scan,
            d.ultimo_error,
            (SELECT count(*)::int FROM credexp_accounts a
              WHERE a.domain = d.domain AND a.estado <> 'dismissed') AS expuestas
       FROM credexp_domains d ORDER BY d.domain`
  );
}

export async function addDomain(domainRaw: string): Promise<CredDomain> {
  const domain = domainRaw.trim().toLowerCase().replace(/^@/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new HttpError(400, 'Dominio inválido');
  await query(
    `INSERT INTO credexp_domains (domain) VALUES ($1)
     ON CONFLICT (domain) DO UPDATE SET habilitado = true`,
    [domain]
  );
  const [d] = await listDomains().then((xs) => xs.filter((x) => x.domain === domain));
  return d;
}

export async function removeDomain(domain: string): Promise<void> {
  await query('DELETE FROM credexp_accounts WHERE domain = $1', [domain]);
  await query('DELETE FROM credexp_domains WHERE domain = $1', [domain]);
}

// --------------------------------------------------------------------------
// Escaneo
// --------------------------------------------------------------------------

/** Refresca el catalogo local de brechas (metadatos publicos, sin clave). */
export async function refreshBreachCatalog(): Promise<number> {
  const { status, body } = await hibpGet<Array<{
    Name: string; Title: string; BreachDate: string; PwnCount: number;
    DataClasses: string[]; IsSensitive: boolean;
  }>>('/api/v3/breaches');
  if (status !== 200 || !Array.isArray(body)) return 0;
  for (const b of body) {
    await query(
      `INSERT INTO credexp_breaches (name, title, breach_date, pwn_count, data_classes, is_sensitive, actualizado)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6, now())
       ON CONFLICT (name) DO UPDATE SET title=$2, breach_date=$3, pwn_count=$4,
         data_classes=$5::jsonb, is_sensitive=$6, actualizado=now()`,
      [b.Name, b.Title ?? null, b.BreachDate || null, b.PwnCount ?? null,
       JSON.stringify(b.DataClasses ?? []), Boolean(b.IsSensitive)]
    );
  }
  return body.length;
}

/**
 * Escanea un dominio: consulta HIBP domain search, hace upsert de las cuentas
 * expuestas y devuelve cuantas son NUEVAS respecto al estado previo.
 */
export async function scanDomain(domain: string): Promise<{ total: number; nuevas: number }> {
  if (!isHibpConfigured()) throw new HttpError(503, 'HIBP_API_KEY no configurada');

  let resp = await hibpGet<Record<string, string[]>>(`/api/v3/breacheddomain/${encodeURIComponent(domain)}`);
  if (resp.status === 429) { await sleep(2500); resp = await hibpGet<Record<string, string[]>>(`/api/v3/breacheddomain/${encodeURIComponent(domain)}`); }

  // Guarda el error de forma legible y marca el dominio como no-verificado.
  const failVerif = async (msg: string): Promise<void> => {
    await query('UPDATE credexp_domains SET ultimo_scan=now(), ultimo_error=$2, verificado=false WHERE domain=$1', [domain, msg]);
  };
  if (resp.status === 401) {
    const m = 'HIBP rechazó la clave (401). Revisa HIBP_API_KEY en la configuración.';
    await failVerif(m); throw new HttpError(401, m);
  }
  if (resp.status === 400 && /no domains have been registered/i.test(resp.raw)) {
    // Caso más común al arrancar: la clave sirve, pero el dominio no está dado de alta
    // en el dashboard de Domain Search de HIBP. Mensaje accionable en vez de "status 400".
    const m = `El dominio no está registrado en tu panel de HIBP Domain Search. Agrégalo y verifica la propiedad en https://haveibeenpwned.com/DomainSearch antes de escanear.`;
    await failVerif(m); throw new HttpError(400, m);
  }
  if (resp.status === 403) {
    const m = 'HIBP: dominio no verificado (403). Completa la verificación de propiedad en el panel de HIBP Domain Search.';
    await failVerif(m); throw new HttpError(403, m);
  }
  if (resp.status === 404) {
    // 404 = dominio verificado y sin cuentas en brechas conocidas: resultado SANO.
    await query('UPDATE credexp_domains SET ultimo_scan=now(), ultimo_error=NULL, verificado=true WHERE domain=$1', [domain]);
    return { total: 0, nuevas: 0 };
  }
  if (resp.status !== 200 || !resp.body || typeof resp.body !== 'object') {
    const m = `HIBP respondió ${resp.status}${resp.raw ? ': ' + resp.raw.slice(0, 160) : ''}`;
    await failVerif(m); throw new HttpError(502, m);
  }

  const mapa = resp.body; // { "usuario": ["Adobe","LinkedIn"], ... }
  const aliases = Object.keys(mapa);
  let nuevas = 0;
  for (const alias of aliases) {
    const brechas = Array.isArray(mapa[alias]) ? mapa[alias] : [];
    const prev = await query<{ id: string }>(
      'SELECT id FROM credexp_accounts WHERE domain=$1 AND alias=$2', [domain, alias]
    );
    if (prev.length === 0) nuevas++;
    await query(
      `INSERT INTO credexp_accounts (domain, alias, brechas, num_brechas, ultima_vez)
       VALUES ($1,$2,$3::jsonb,$4, now())
       ON CONFLICT (domain, alias) DO UPDATE
         SET brechas=$3::jsonb, num_brechas=$4, ultima_vez=now(),
             estado = CASE WHEN credexp_accounts.estado='dismissed' THEN 'dismissed' ELSE 'open' END`,
      [domain, alias, JSON.stringify(brechas), brechas.length]
    );
  }
  await query('UPDATE credexp_domains SET ultimo_scan=now(), ultimo_error=NULL, verificado=true WHERE domain=$1', [domain]);
  return { total: aliases.length, nuevas };
}

/** Escanea todos los dominios habilitados. Devuelve el resumen por dominio. */
export async function scanAll(): Promise<{ domain: string; total: number; nuevas: number; error?: string }[]> {
  const doms = await query<{ domain: string }>('SELECT domain FROM credexp_domains WHERE habilitado = true');
  const out: { domain: string; total: number; nuevas: number; error?: string }[] = [];
  for (const { domain } of doms) {
    try {
      const r = await scanDomain(domain);
      out.push({ domain, ...r });
    } catch (e) {
      out.push({ domain, total: 0, nuevas: 0, error: e instanceof Error ? e.message : 'error' });
    }
    await sleep(1600); // respeta el rate limit de HIBP
  }
  return out;
}

// --------------------------------------------------------------------------
// Consulta
// --------------------------------------------------------------------------

export async function listAccounts(f: { domain?: string; estado?: string; q?: string } = {}): Promise<CredAccount[]> {
  const cond: string[] = [];
  const args: unknown[] = [];
  if (f.domain) { args.push(f.domain); cond.push(`domain = $${args.length}`); }
  if (f.estado) { args.push(f.estado); cond.push(`estado = $${args.length}`); }
  if (f.q) { args.push(`%${f.q.toLowerCase()}%`); cond.push(`lower(alias) LIKE $${args.length}`); }
  const where = cond.length ? `WHERE ${cond.join(' AND ')}` : '';
  return query<CredAccount>(
    `SELECT id, domain, alias, brechas, num_brechas, estado,
            to_char(primera_vez,'YYYY-MM-DD"T"HH24:MI:SSOF') AS primera_vez,
            to_char(ultima_vez ,'YYYY-MM-DD"T"HH24:MI:SSOF') AS ultima_vez
       FROM credexp_accounts ${where}
      ORDER BY num_brechas DESC, alias ASC LIMIT 500`,
    args
  );
}

export async function setStatus(id: string, estado: 'open' | 'ack' | 'dismissed', userId: string | null): Promise<void> {
  if (!['open', 'ack', 'dismissed'].includes(estado)) throw new HttpError(400, 'Estado inválido');
  await query(
    `UPDATE credexp_accounts SET estado=$2, ack_por=$3, ack_en=now() WHERE id=$1`,
    [id, estado, userId]
  );
}

export async function getSummary(): Promise<{
  configurado: boolean;
  dominios: CredDomain[];
  totalExpuestas: number;
  abiertas: number;
  cuentasCriticas: number;
  topBrechas: { name: string; title: string | null; cuentas: number }[];
  ultimoScan: string | null;
}> {
  const dominios = await listDomains();
  const [{ total } = { total: 0 }] = await query<{ total: number }>(
    `SELECT count(*)::int AS total FROM credexp_accounts WHERE estado <> 'dismissed'`
  );
  const [{ abiertas } = { abiertas: 0 }] = await query<{ abiertas: number }>(
    `SELECT count(*)::int AS abiertas FROM credexp_accounts WHERE estado = 'open'`
  );
  // "criticas": cuentas presentes en 3+ brechas
  const [{ criticas } = { criticas: 0 }] = await query<{ criticas: number }>(
    `SELECT count(*)::int AS criticas FROM credexp_accounts WHERE estado <> 'dismissed' AND num_brechas >= 3`
  );
  const topBrechas = await query<{ name: string; title: string | null; cuentas: number }>(
    `SELECT b.value AS name,
            (SELECT title FROM credexp_breaches WHERE name = b.value) AS title,
            count(*)::int AS cuentas
       FROM credexp_accounts a, jsonb_array_elements_text(a.brechas) AS b(value)
      WHERE a.estado <> 'dismissed'
      GROUP BY b.value ORDER BY cuentas DESC LIMIT 10`
  );
  const ultimo = dominios.map((d) => d.ultimo_scan).filter(Boolean).sort().pop() ?? null;
  return {
    configurado: isHibpConfigured(),
    dominios,
    totalExpuestas: total,
    abiertas,
    cuentasCriticas: criticas,
    topBrechas,
    ultimoScan: ultimo,
  };
}

// --------------------------------------------------------------------------
// Diagnóstico de prerequisitos (estado real de la cuenta HIBP, en vivo)
// --------------------------------------------------------------------------

export interface HibpDiagnostics {
  keyConfigured: boolean;
  keyValid: boolean | null;
  plan: { name: string; description: string; subscribedUntil: string; maxBreachedPerDomain: number; rpm: number } | null;
  hibpDomains: { domain: string; pwnCount: number }[]; // registrados + verificados en HIBP
  monitored: { domain: string; registeredInHibp: boolean; verificado: boolean; ultimoScan: string | null; ultimoError: string | null; expuestas: number }[];
  ready: boolean;
  steps: { step: string; detail: string }[];
  checkedAt: string;
}

interface SubStatus { SubscriptionName?: string; Description?: string; SubscribedUntil?: string; DomainSearchMaxBreachedAccounts?: number; Rpm?: number }
interface SubDomain { DomainName?: string; PwnCount?: number | null }

export async function hibpDiagnostics(): Promise<HibpDiagnostics> {
  const checkedAt = new Date().toISOString();
  const monitoredRows = await listDomains();
  const base: HibpDiagnostics = {
    keyConfigured: isHibpConfigured(), keyValid: null, plan: null, hibpDomains: [],
    monitored: monitoredRows.map((d) => ({ domain: d.domain, registeredInHibp: false, verificado: d.verificado, ultimoScan: d.ultimo_scan, ultimoError: d.ultimo_error, expuestas: d.expuestas ?? 0 })),
    ready: false, steps: [], checkedAt,
  };
  if (!base.keyConfigured) {
    base.steps.push({ step: 'Configurar la clave de API de HIBP', detail: 'Obtén una suscripción en https://haveibeenpwned.com/API/Key y define HIBP_API_KEY en la configuración del backend.' });
    return base;
  }

  // 1) ¿La clave es válida? + plan.
  try {
    const sub = await hibpGet<SubStatus>('/api/v3/subscription/status');
    if (sub.status === 200 && sub.body) {
      base.keyValid = true;
      base.plan = {
        name: sub.body.SubscriptionName ?? '—', description: sub.body.Description ?? '',
        subscribedUntil: sub.body.SubscribedUntil ?? '', maxBreachedPerDomain: sub.body.DomainSearchMaxBreachedAccounts ?? 0, rpm: sub.body.Rpm ?? 0,
      };
    } else if (sub.status === 401) {
      base.keyValid = false;
      base.steps.push({ step: 'La clave de HIBP fue rechazada (401)', detail: 'Revisa HIBP_API_KEY: cópiala de nuevo desde el panel de HIBP; asegúrate de que la suscripción esté vigente.' });
      return base;
    }
  } catch { /* red / timeout */ }

  // 2) ¿Qué dominios están registrados y verificados en HIBP?
  try {
    const sd = await hibpGet<SubDomain[]>('/api/v3/subscribeddomains');
    if (sd.status === 200 && Array.isArray(sd.body)) {
      base.hibpDomains = sd.body.filter((x) => x.DomainName).map((x) => ({ domain: String(x.DomainName).toLowerCase(), pwnCount: x.PwnCount ?? 0 }));
    }
  } catch { /* red / timeout */ }

  const hibpSet = new Set(base.hibpDomains.map((d) => d.domain));
  base.monitored = base.monitored.map((m) => ({ ...m, registeredInHibp: hibpSet.has(m.domain) }));
  base.ready = base.monitored.some((m) => m.registeredInHibp);

  // 3) Pasos accionables para los dominios monitoreados que aún no están listos.
  const pendientes = base.monitored.filter((m) => !m.registeredInHibp).map((m) => m.domain);
  if (pendientes.length) {
    base.steps.push({ step: `Registrar en HIBP: ${pendientes.join(', ')}`, detail: 'En https://haveibeenpwned.com/DomainSearch pulsa "Add domain" y escribe el dominio.' });
    base.steps.push({ step: 'Verificar la propiedad del dominio', detail: 'HIBP te dará una opción de verificación: publicar un registro DNS TXT con el token que te muestra, subir un archivo al sitio, agregar un meta-tag, o recibir un correo a admin@/webmaster@/hostmaster@ del dominio. La DNS TXT es la más práctica si controlas el DNS.' });
    base.steps.push({ step: 'Escanear', detail: 'Una vez verificado (aparecerá aquí como registrado ✓), usa "Escanear ahora" y el módulo traerá las cuentas expuestas.' });
  }
  return base;
}

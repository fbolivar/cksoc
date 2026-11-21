/**
 * Exposición de APIs — descubrimiento y postura de las APIs expuestas a Internet
 * del cliente. Reutiliza la superficie que ASM ya descubrió (asm_assets de los
 * dominios AUTORIZADOS) y la sondea por indicadores de API y, sobre todo, por
 * DOCUMENTACION/ESPECIFICACIONES EXPUESTAS (Swagger/OpenAPI, introspección GraphQL,
 * Spring Actuator) — hallazgos reales OWASP API8/API9. Rastrea shadow (nuevas) y
 * zombie (dejaron de responder). Escaneo ACTIVO acotado a dominios propios del
 * cliente (mismo modelo autorizado que ASM): solo GET/introspección, timeouts
 * cortos, set acotado de rutas, solo IPs publicas.
 */
import { randomUUID } from 'node:crypto';
import { promises as dns } from 'node:dns';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { isPublicIP } from '../geo/geoip.service';

const UA = 'HexWatch-API-Scanner/1.0';
const TIMEOUT = 3000;
const MAX_HOSTS = 40;
const POOL = 5;

type Sev = 'alta' | 'media' | 'baja';

const SPEC_PATHS = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs', '/swagger', '/swagger-ui.html', '/swagger-ui/', '/.well-known/openapi', '/actuator', '/actuator/health', '/api/swagger.json'];
const API_PATHS = ['/api', '/api/', '/v1', '/v2', '/rest'];

export interface ApiEndpoint {
  id: string; host: string; ip: string | null; scheme: string; puerto: number;
  esApi: boolean; tipo: string; specExpuesto: boolean;
  hallazgos: { titulo: string; severidad: Sev; owasp: string; evidencia: string }[];
  severidad: Sev; primeraVez: string; ultimaVez: string;
}
export interface ApiExposureReport {
  ultimoScan: string | null;
  resumen: { total: number; apis: number; specsExpuestos: number; nuevos: number; zombies: number };
  endpoints: ApiEndpoint[];
}

let schemaReady = false;
export async function ensureApiExposureSchema(): Promise<void> {
  if (schemaReady) return;
  await query(`CREATE TABLE IF NOT EXISTS api_endpoints (
    id uuid PRIMARY KEY,
    host text NOT NULL,
    ip text,
    scheme text NOT NULL DEFAULT 'https',
    puerto int NOT NULL DEFAULT 443,
    es_api boolean NOT NULL DEFAULT false,
    tipo text NOT NULL DEFAULT 'web',
    spec_expuesto boolean NOT NULL DEFAULT false,
    hallazgos jsonb NOT NULL DEFAULT '[]'::jsonb,
    severidad text NOT NULL DEFAULT 'baja',
    primera_vez timestamptz NOT NULL DEFAULT now(),
    ultima_vez timestamptz NOT NULL DEFAULT now(),
    UNIQUE (host, puerto)
  )`);
  schemaReady = true;
}

interface ProbeRes { status: number; ctype: string; body: string; ok: boolean }
async function probe(url: string, method: 'GET' | 'POST' = 'GET', body?: string): Promise<ProbeRes | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const r = await fetch(url, {
      method, body,
      headers: { 'User-Agent': UA, Accept: 'application/json,text/html', ...(body ? { 'Content-Type': 'application/json' } : {}) },
      signal: ctrl.signal, redirect: 'manual',
    });
    const ctype = r.headers.get('content-type') ?? '';
    const txt = (await r.text().catch(() => '')).slice(0, 4000);
    return { status: r.status, ctype, body: txt, ok: r.status >= 200 && r.status < 400 };
  } catch { return null; }
  finally { clearTimeout(t); }
}

function looksOpenApi(b: string): boolean { try { const j = JSON.parse(b); return !!(j.openapi || j.swagger || (j.paths && typeof j.paths === 'object')); } catch { return /"openapi"\s*:|"swagger"\s*:/.test(b); } }
function looksSwaggerUi(b: string): boolean { return /swagger-ui|SwaggerUIBundle|<title>\s*Swagger/i.test(b); }
function looksActuator(b: string): boolean { try { const j = JSON.parse(b); return !!(j._links || j.status === 'UP' || j.components); } catch { return false; } }

async function candidateHosts(): Promise<{ host: string; ip: string | null }[]> {
  const assets = await query<{ host: string; ip: string }>('SELECT DISTINCT host, ip FROM asm_assets WHERE activo = true').catch(() => []);
  const map = new Map<string, string | null>();
  for (const a of assets) if (!map.has(a.host)) map.set(a.host, a.ip);
  // Sumar subdominios tipicos de API de los dominios autorizados
  const domains = await query<{ domain: string }>('SELECT domain FROM asm_domains WHERE habilitado = true').catch(() => []);
  for (const d of domains) {
    for (const p of ['api', 'gateway', 'rest', 'apigw']) {
      const h = `${p}.${d.domain}`;
      if (map.has(h)) continue;
      try { const ips = await dns.resolve4(h); const ip = ips.find(isPublicIP); if (ip) map.set(h, ip); } catch { /* no resuelve */ }
    }
  }
  return [...map.entries()].filter(([, ip]) => !ip || isPublicIP(ip)).slice(0, MAX_HOSTS).map(([host, ip]) => ({ host, ip }));
}

async function scanHost(host: string, ip: string | null): Promise<Omit<ApiEndpoint, 'id' | 'primeraVez' | 'ultimaVez'>> {
  const hallazgos: ApiEndpoint['hallazgos'] = [];
  let esApi = false, specExpuesto = false, tipo = 'web', scheme = 'https', puerto = 443;

  // esquema que responde (https, fallback http)
  let base = `https://${host}`;
  let root = await probe(base);
  if (!root) { const r2 = await probe(`http://${host}`); if (r2) { base = `http://${host}`; scheme = 'http'; puerto = 80; root = r2; } }
  if (!root) return { host, ip, scheme, puerto, esApi: false, tipo: 'sin-respuesta', specExpuesto: false, hallazgos: [], severidad: 'baja' };

  // Specs/docs + GraphQL + API en PARALELO (rápido)
  const [specRes, apiRes, gq] = await Promise.all([
    Promise.all(SPEC_PATHS.map(async (p) => ({ p, r: await probe(base + p) }))),
    Promise.all(API_PATHS.map(async (p) => ({ p, r: await probe(base + p) }))),
    probe(base + '/graphql', 'POST', JSON.stringify({ query: '{__schema{types{name}}}' })),
  ]);

  for (const { p, r } of specRes) {
    if (!r || !r.ok) continue;
    if (p.includes('actuator') && looksActuator(r.body)) {
      specExpuesto = true; esApi = true; tipo = 'Spring Actuator';
      hallazgos.push({ titulo: `Spring Actuator expuesto (${p})`, severidad: 'alta', owasp: 'API8: configuracion incorrecta', evidencia: `HTTP ${r.status} con endpoints de gestion` });
    } else if (looksOpenApi(r.body)) {
      specExpuesto = true; esApi = true; if (tipo === 'web') tipo = 'REST (OpenAPI)';
      hallazgos.push({ titulo: `Especificacion OpenAPI/Swagger expuesta (${p})`, severidad: 'alta', owasp: 'API9: inventario impropio / API8', evidencia: `HTTP ${r.status}, revela rutas y estructura de la API` });
    } else if (looksSwaggerUi(r.body)) {
      specExpuesto = true; esApi = true; if (tipo === 'web') tipo = 'Docs/Swagger UI';
      hallazgos.push({ titulo: `Swagger UI expuesto (${p})`, severidad: 'alta', owasp: 'API8: configuracion incorrecta', evidencia: `HTTP ${r.status}, documentacion de la API publica` });
    }
  }
  if (gq && gq.ok && /__schema|queryType|"types"/.test(gq.body)) {
    esApi = true; specExpuesto = true; tipo = 'GraphQL';
    hallazgos.push({ titulo: 'Introspeccion de GraphQL habilitada (/graphql)', severidad: 'alta', owasp: 'API8/API9: expone el esquema completo', evidencia: 'La introspeccion devuelve el __schema' });
  }
  // API real = responde JSON en una ruta de API (NO solo por el nombre del subdominio:
  // los wildcard DNS api.* que devuelven el sitio web NO son APIs).
  for (const { p, r } of apiRes) {
    if (r && r.ok && /json/i.test(r.ctype)) {
      esApi = true; if (tipo === 'web') tipo = 'REST';
      hallazgos.push({ titulo: `Endpoint de API accesible sin autenticacion aparente (${p})`, severidad: 'media', owasp: 'API1/API9: revisar control de acceso', evidencia: `HTTP ${r.status} JSON` });
      break;
    }
  }

  const sev: Sev = hallazgos.some((h) => h.severidad === 'alta') ? 'alta' : hallazgos.some((h) => h.severidad === 'media') ? 'media' : 'baja';
  return { host, ip, scheme, puerto, esApi, tipo: esApi ? tipo : 'web', specExpuesto, hallazgos, severidad: sev };
}

export async function scanApiExposure(): Promise<{ hosts: number; apis: number; specs: number }> {
  await ensureApiExposureSchema();
  const hosts = await candidateHosts();
  let apis = 0, specs = 0;
  // Pool de concurrencia: hosts en lotes, cada host sondea sus rutas en paralelo.
  for (let i = 0; i < hosts.length; i += POOL) {
    const batch = hosts.slice(i, i + POOL);
    const results = await Promise.all(batch.map(async ({ host, ip }) => {
      try { return { host, ip, r: await scanHost(host, ip) }; }
      catch (e) { logger.warn({ e, host }, 'api-exposure: scanHost'); return null; }
    }));
    for (const item of results) {
      if (!item) continue;
      const { host, ip, r } = item;
      if (r.esApi) apis++;
      if (r.specExpuesto) specs++;
      await query(
        `INSERT INTO api_endpoints (id, host, ip, scheme, puerto, es_api, tipo, spec_expuesto, hallazgos, severidad, primera_vez, ultima_vez)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), now())
         ON CONFLICT (host, puerto) DO UPDATE SET
           ip=EXCLUDED.ip, scheme=EXCLUDED.scheme, es_api=EXCLUDED.es_api, tipo=EXCLUDED.tipo,
           spec_expuesto=EXCLUDED.spec_expuesto, hallazgos=EXCLUDED.hallazgos, severidad=EXCLUDED.severidad, ultima_vez=now()`,
        [randomUUID(), host, ip, r.scheme, r.puerto, r.esApi, r.tipo, r.specExpuesto, JSON.stringify(r.hallazgos), r.severidad],
      ).catch((e) => logger.warn({ e }, 'api-exposure: upsert'));
    }
  }
  return { hosts: hosts.length, apis, specs };
}

export async function getApiExposure(): Promise<ApiExposureReport> {
  await ensureApiExposureSchema();
  const rows = await query<{ id: string; host: string; ip: string | null; scheme: string; puerto: number; es_api: boolean; tipo: string; spec_expuesto: boolean; hallazgos: ApiEndpoint['hallazgos']; severidad: Sev; primera_vez: string; ultima_vez: string }>(
    'SELECT * FROM api_endpoints ORDER BY (severidad=\'alta\') DESC, es_api DESC, host',
  ).catch(() => []);
  const ultimoScan = rows.reduce<string | null>((max, r) => (!max || r.ultima_vez > max ? r.ultima_vez : max), null);
  const endpoints: ApiEndpoint[] = rows.map((r) => ({
    id: r.id, host: r.host, ip: r.ip, scheme: r.scheme, puerto: r.puerto, esApi: r.es_api, tipo: r.tipo,
    specExpuesto: r.spec_expuesto, hallazgos: r.hallazgos ?? [], severidad: r.severidad,
    primeraVez: r.primera_vez, ultimaVez: r.ultima_vez,
  }));
  const apis = endpoints.filter((e) => e.esApi);
  const nuevos = ultimoScan ? apis.filter((e) => e.primeraVez >= (ultimoScan.slice(0, 10)) && new Date(ultimoScan).getTime() - new Date(e.primeraVez).getTime() < 36e5).length : 0;
  const zombies = ultimoScan ? apis.filter((e) => new Date(ultimoScan).getTime() - new Date(e.ultimaVez).getTime() > 3600_000).length : 0;
  return {
    ultimoScan,
    resumen: { total: endpoints.length, apis: apis.length, specsExpuestos: endpoints.filter((e) => e.specExpuesto).length, nuevos, zombies },
    endpoints,
  };
}

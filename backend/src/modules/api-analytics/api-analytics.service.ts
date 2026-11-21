/**
 * Analítica de API por endpoint (#C del plan API Radware) — cierra lo que la
 * vista de red no puede ver: BOLA/broken-auth/function-level-auth REALES, a
 * partir de los LOGS HTTP (web-accesslog) que Wazuh ya decodifica de los
 * servidores web monitoreados (data.url, data.protocol, data.srcip, data.id).
 *
 * Hoy la fuente con cobertura es la propia API de HexWatch (agente cs-soc-app):
 *   - valor de AUTO-DEFENSA (detecta enumeración/abuso contra el panel), y
 *   - es la ruta de ONBOARDING: el mismo <localfile> del access.log se aplica
 *     al web server del cliente para extender la cobertura a su API.
 *
 * Trabaja sobre las ALERTAS web de Wazuh (4xx/5xx/escaneo), no sobre cada 200,
 * para no inflar el índice. En vivo, sin persistencia.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { isPublicIP } from '../geo/geoip.service';

const RANGE: Record<string, string> = { '1h': 'now-1h', '24h': 'now-24h', '7d': 'now-7d' };

const AUTHFAIL_MIN = Number(process.env.APIAN_AUTHFAIL_MIN) || 8;   // 401/403 por endpoint
const ENUM_MIN_URLS = Number(process.env.APIAN_ENUM_URLS) || 12;    // urls distintas por IP (enumeración)
const SRVERR_MIN = Number(process.env.APIAN_SRVERR_MIN) || 8;       // 5xx por endpoint

export type Sev = 'alta' | 'media' | 'baja' | 'info';
export interface ApiEndpointStat {
  endpoint: string; metodos: string[]; hits: number;
  status: Record<string, number>; fuentesIp: number; topIps: string[];
  authFails: number; notFound: number; serverErrors: number; flag: Sev;
}
export interface ApiHallazgo {
  tipo: string; owasp: string; severidad: Sev; titulo: string; detalle: string; evidencia: string[];
  externa: boolean; // el origen es una IP pública (amenaza externa) vs interna/confiable
}
export interface ApiAnalyticsReport {
  range: string; generadoEn: string;
  cobertura: boolean;
  fuentes: { name: string; eventos: number }[];
  resumen: { eventos: number; endpoints: number; authFails: number; enumeracion: number; serverErrors: number };
  endpoints: ApiEndpointStat[];
  hallazgos: ApiHallazgo[];
}

type Bkt = { key: string | number; doc_count: number; [k: string]: unknown };
const bkts = (o: unknown): Bkt[] => (o as { buckets?: Bkt[] } | undefined)?.buckets ?? [];
const card = (o: unknown): number => (o as { value?: number } | undefined)?.value ?? 0;
/** Clave de endpoint: sin query-string y con los segmentos tipo id normalizados a :id. */
function endpointKey(url: string): string {
  const path = (url || '').split('?')[0];
  return path.replace(/\/\d+(?=\/|$)/g, '/:id')
             .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, '/:uuid')
             .replace(/\/[0-9a-f]{24,}(?=\/|$)/gi, '/:hash') || '/';
}

export async function getApiAnalytics(rangeIn = '24h'): Promise<ApiAnalyticsReport> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const c = getIndexerClient();
  const base = {
    bool: {
      filter: [
        { range: { timestamp: { gte: RANGE[range] } } },
        { exists: { field: 'data.url' } },
      ],
    },
  };

  const resp = await c.post<{ hits?: { total?: { value?: number } }; aggregations?: Record<string, unknown> }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 0,
      query: base,
      aggs: {
        fuentes: { terms: { field: 'agent.name', size: 20 } },
        endpoints: {
          terms: { field: 'data.url', size: 200 },
          aggs: {
            metodos: { terms: { field: 'data.protocol', size: 5 } },
            status: { terms: { field: 'data.id', size: 10 } },
            ips: { cardinality: { field: 'data.srcip' } },
            top_ips: { terms: { field: 'data.srcip', size: 3 } },
          },
        },
        por_ip: {
          terms: { field: 'data.srcip', size: 50 },
          aggs: {
            urls: { cardinality: { field: 'data.url' } },
            status: { terms: { field: 'data.id', size: 8 } },
            top_urls: { terms: { field: 'data.url', size: 6 } },
          },
        },
        reglas: { terms: { field: 'rule.id', size: 15 } },
      },
    },
  );

  const agg = resp.data.aggregations ?? {};
  const eventos = resp.data.hits?.total?.value ?? 0;
  const fuentes = bkts(agg.fuentes).map((b) => ({ name: String(b.key), eventos: b.doc_count }));
  const cobertura = fuentes.length > 0 && eventos > 0;

  const is4xxAuth = (s: string) => s === '401' || s === '403';
  const is5xx = (s: string) => /^5\d\d$/.test(s);

  // Agrupar endpoints por clave normalizada
  const map = new Map<string, ApiEndpointStat>();
  for (const b of bkts(agg.endpoints)) {
    const key = endpointKey(String(b.key));
    const e = map.get(key) ?? { endpoint: key, metodos: [], hits: 0, status: {}, fuentesIp: 0, topIps: [], authFails: 0, notFound: 0, serverErrors: 0, flag: 'info' as Sev };
    e.hits += b.doc_count;
    for (const m of bkts(b.metodos)) if (!e.metodos.includes(String(m.key))) e.metodos.push(String(m.key));
    for (const s of bkts(b.status)) {
      const code = String(s.key); e.status[code] = (e.status[code] ?? 0) + s.doc_count;
      if (is4xxAuth(code)) e.authFails += s.doc_count;
      if (code === '404') e.notFound += s.doc_count;
      if (is5xx(code)) e.serverErrors += s.doc_count;
    }
    e.fuentesIp = Math.max(e.fuentesIp, card(b.ips));
    for (const ip of bkts(b.top_ips).map((x) => String(x.key))) if (!e.topIps.includes(ip)) e.topIps.push(ip);
    map.set(key, e);
  }
  const endpoints = [...map.values()].sort((a, b) => b.hits - a.hits);
  for (const e of endpoints) {
    e.topIps = e.topIps.slice(0, 3);
    e.flag = e.authFails >= AUTHFAIL_MIN ? 'alta' : e.serverErrors >= SRVERR_MIN ? 'media' : e.notFound >= AUTHFAIL_MIN ? 'media' : 'info';
  }

  // --- Hallazgos OWASP ---
  const hallazgos: ApiHallazgo[] = [];

  // API2 Broken Authentication: endpoints con muchos 401/403
  const authEp = endpoints.filter((e) => e.authFails >= AUTHFAIL_MIN).sort((a, b) => b.authFails - a.authFails);
  for (const e of authEp.slice(0, 8)) {
    const externa = e.topIps.some((ip) => isPublicIP(ip));
    hallazgos.push({
      tipo: 'auth-fail', owasp: 'API2: Broken Authentication', severidad: e.authFails >= AUTHFAIL_MIN * 3 ? 'alta' : 'media',
      titulo: `${e.authFails} fallos de autenticación (401/403) en ${e.endpoint}`,
      detalle: `${e.fuentesIp} IP(s) origen${externa ? '' : ' (interno/confiable)'}; métodos ${e.metodos.join('/')}.`,
      evidencia: [`${e.endpoint} · 401:${e.status['401'] ?? 0} 403:${e.status['403'] ?? 0}`, ...e.topIps.map((ip) => `origen ${ip}`)],
      externa,
    });
  }

  // API5 Broken Function Level Authorization: 403 (prohibido = intentó función privilegiada)
  const forbidden = endpoints.filter((e) => (e.status['403'] ?? 0) > 0).sort((a, b) => (b.status['403'] ?? 0) - (a.status['403'] ?? 0));
  for (const e of forbidden.slice(0, 5)) {
    const externa = e.topIps.some((ip) => isPublicIP(ip));
    hallazgos.push({
      tipo: 'forbidden', owasp: 'API5: Broken Function Level Authorization', severidad: 'media',
      titulo: `${e.status['403']} respuesta(s) 403 (prohibido) en ${e.endpoint}`,
      detalle: `Intentos de acceder a funciones/recursos sin autorización de nivel${externa ? '' : ' (interno/confiable)'}.`,
      evidencia: [`${e.endpoint}`, ...e.topIps.map((ip) => `origen ${ip}`)],
      externa,
    });
  }

  // API1 BOLA / enumeración: una IP que toca MUCHAS urls distintas con 4xx
  let enumeracion = 0;
  for (const b of bkts(agg.por_ip)) {
    const distinct = card(b.urls);
    const st = Object.fromEntries(bkts(b.status).map((s) => [String(s.key), s.doc_count]));
    const fourxx = Object.entries(st).filter(([k]) => /^4\d\d$/.test(k)).reduce((a, [, v]) => a + (v as number), 0);
    if (distinct >= ENUM_MIN_URLS && fourxx >= ENUM_MIN_URLS) {
      enumeracion++;
      const externa = isPublicIP(String(b.key));
      hallazgos.push({
        tipo: 'enumeracion', owasp: 'API1: Broken Object Level Authorization (BOLA)', severidad: externa && distinct >= ENUM_MIN_URLS * 2 ? 'alta' : 'media',
        titulo: `IP ${b.key} enumeró ${distinct} endpoints distintos (${fourxx} respuestas 4xx)`,
        detalle: externa ? 'Patrón de enumeración/sondeo de objetos desde IP externa — posible BOLA o recon de API.' : 'Ráfaga de 4xx desde IP interna/confiable (p. ej. token expirado del propio panel); no se trata como amenaza externa.',
        evidencia: bkts(b.top_urls).slice(0, 5).map((u) => endpointKey(String(u.key))),
        externa,
      });
    }
  }

  // Errores de servidor por endpoint (API8 / disponibilidad)
  const srvEp = endpoints.filter((e) => e.serverErrors >= SRVERR_MIN).sort((a, b) => b.serverErrors - a.serverErrors);
  for (const e of srvEp.slice(0, 5)) {
    hallazgos.push({
      tipo: 'server-error', owasp: 'API8: Security Misconfiguration', severidad: 'media',
      titulo: `${e.serverErrors} error(es) 5xx en ${e.endpoint}`,
      detalle: 'Errores del servidor repetidos: posible mala configuración o condición no controlada.',
      evidencia: [Object.entries(e.status).filter(([k]) => /^5/.test(k)).map(([k, v]) => `${k}:${v}`).join(' ')],
      externa: false,
    });
  }

  // Escaneo/recon web (regla 31151 y familia web_scan)
  const scanRules = new Set(['31151', '31152', '31153', '31154', '31164', '31165', '31166']);
  const scanHits = bkts(agg.reglas).filter((r) => scanRules.has(String(r.key))).reduce((a, r) => a + r.doc_count, 0);
  if (scanHits > 0) {
    hallazgos.push({
      tipo: 'recon', owasp: 'API9: Improper Inventory Management / recon', severidad: 'media',
      titulo: `${scanHits} evento(s) de escaneo web detectados`,
      detalle: 'Múltiples errores 4xx desde un mismo origen (regla de escaneo/recon de Wazuh).',
      evidencia: ['reglas web_scan/recon activadas'],
      externa: false,
    });
  }

  hallazgos.sort((a, b) => (a.severidad === 'alta' ? -1 : 1) - (b.severidad === 'alta' ? -1 : 1));

  return {
    range, generadoEn: new Date().toISOString(), cobertura, fuentes,
    resumen: {
      eventos, endpoints: endpoints.length,
      authFails: endpoints.reduce((a, e) => a + e.authFails, 0),
      enumeracion, serverErrors: endpoints.reduce((a, e) => a + e.serverErrors, 0),
    },
    endpoints: endpoints.slice(0, 60),
    hallazgos,
  };
}

/** Resumen de cobertura para el scorecard de Amenazas de API (#B). */
export interface ApiCoverage {
  cobertura: boolean; fuentes: string[];
  bola: ApiHallazgo[]; auth: ApiHallazgo[]; funcion: ApiHallazgo[];
}
export async function getApiHttpCoverage(range = '24h'): Promise<ApiCoverage> {
  try {
    const r = await getApiAnalytics(range);
    // Solo los hallazgos de origen EXTERNO (IP pública) encienden el scorecard:
    // una amenaza de API se mide contra el servicio expuesto, no el tráfico interno.
    return {
      cobertura: r.cobertura, fuentes: r.fuentes.map((f) => f.name),
      bola: r.hallazgos.filter((h) => h.tipo === 'enumeracion' && h.externa),
      auth: r.hallazgos.filter((h) => h.tipo === 'auth-fail' && h.externa),
      funcion: r.hallazgos.filter((h) => h.tipo === 'forbidden' && h.externa),
    };
  } catch {
    return { cobertura: false, fuentes: [], bola: [], auth: [], funcion: [] };
  }
}

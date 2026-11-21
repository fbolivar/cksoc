/**
 * Amenazas de API — scorecard OWASP API Security Top 10 (2023) construido por
 * CORRELACION de lo que HexWatch ya detecta a nivel de red/perímetro, sin estar
 * inline: DDoS/Bots (SonicWall) y Exposición de APIs (ASM). Marca honestamente
 * las categorías que requieren inspección de payloads HTTP (API1/3/5) como
 * "sin cobertura — requiere enviar los logs HTTP del cliente" (#C del plan).
 */
import { getDdosBots } from '../ddos/ddos.service';
import { getApiExposure } from '../api-exposure/api-exposure.service';
import { getApiHttpCoverage, type ApiCoverage } from '../api-analytics/api-analytics.service';

export type Estado = 'detectado' | 'limpio' | 'sin-cobertura';
export type Sev = 'alta' | 'media' | 'baja' | 'info';
export interface ApiCategoria {
  id: string; nombre: string; estado: Estado; severidad: Sev;
  count: number; evidencia: string[]; fuente: string; ruta: string | null; descripcion: string;
}
export interface ApiThreatsReport {
  range: string; generadoEn: string;
  resumen: { detectadas: number; limpias: number; sinCobertura: number };
  categorias: ApiCategoria[];
}

const SINCOB = (id: string, nombre: string, descripcion: string): ApiCategoria => ({
  id, nombre, estado: 'sin-cobertura', severidad: 'info', count: 0, evidencia: [],
  fuente: 'Requiere logs HTTP del cliente (#C: enviar access logs a Wazuh)', ruta: null, descripcion,
});

export async function getApiThreats(rangeIn = '24h'): Promise<ApiThreatsReport> {
  const range = ['1h', '24h', '7d'].includes(rangeIn) ? rangeIn : '24h';
  const [ddos, exp, cov] = await Promise.all([
    getDdosBots(range).catch(() => ({ volumetric: [], bots: [], resumen: { flujos: 0, volumetricos: 0, bots: 0 } })),
    getApiExposure().catch(() => ({ ultimoScan: null, resumen: { total: 0, apis: 0, specsExpuestos: 0, nuevos: 0, zombies: 0 }, endpoints: [] })),
    getApiHttpCoverage(range).catch((): ApiCoverage => ({ cobertura: false, fuentes: [], bola: [], auth: [], funcion: [] })),
  ]);
  const fuenteHttp = `Analítica HTTP por endpoint (${cov.fuentes.join(', ') || 'sin fuentes'})`;

  // Solo las señales dirigidas a puertos web/API cuentan como "amenazas de API":
  // el abuso de credenciales a telnet/RDP/PPTP, etc. es perímetro (vive en /ddos),
  // no OWASP API. Esto evita sobre-reportar cobertura de API en el informe.
  const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443, 4443, 2053, 2083, 2087, 2096]);
  const esWeb = (p: number) => WEB_PORTS.has(p);
  // El objetivo debe ser una IP pública: una amenaza de API se mide contra el
  // servicio expuesto a Internet, no contra infra interna/SOC (RFC1918/loopback).
  const esPublica = (ip: string) => {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
    if (!m) return false;
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)) return false;
    return true;
  };
  const esApiTarget = (p: number, target: string) => esWeb(p) && esPublica(target);

  // Clasificar señales de ddos (acotadas a puertos web/API con objetivo público)
  const credStuffing = ddos.bots.filter((b) => (b.tipo === 'credential-stuffing' || b.tipo === 'bot') && esApiTarget(b.topPort, b.target));
  const scraping = ddos.bots.filter((b) => b.tipo === 'scraping' && esApiTarget(b.topPort, b.target));
  const httpFlood = ddos.bots.filter((b) => b.tipo === 'http-flood' && esApiTarget(b.topPort, b.target));
  const volum = ddos.volumetric.filter((v) => esApiTarget(v.topPort, v.target)); // fan-in / flood / amplificacion a web/API público
  const specs = exp.endpoints.filter((e) => e.specExpuesto);
  const shadowZombie = exp.resumen.nuevos + exp.resumen.zombies;

  const det = (count: number, sev: Sev): Estado => (count > 0 ? 'detectado' : 'limpio');

  const categorias: ApiCategoria[] = [
    // API1 BOLA: ahora observable vía analítica HTTP por endpoint (#C) si hay cobertura.
    cov.cobertura
      ? {
          id: 'API1', nombre: 'Broken Object Level Authorization (BOLA)', estado: cov.bola.length ? 'detectado' : 'limpio',
          severidad: cov.bola.some((h) => h.severidad === 'alta') ? 'alta' : cov.bola.length ? 'media' : 'baja',
          count: cov.bola.length,
          evidencia: cov.bola.slice(0, 6).map((h) => h.titulo),
          fuente: fuenteHttp, ruta: '/analitica-api',
          descripcion: 'Enumeración/sondeo de objetos por IP (acceso a objetos de otros usuarios). Observable por analítica de logs HTTP por endpoint.',
        }
      : SINCOB('API1', 'Broken Object Level Authorization (BOLA)', 'Acceso a objetos de otros usuarios manipulando IDs. Se detecta por patrones de acceso a nivel de endpoint/payload.'),
    {
      id: 'API2', nombre: 'Broken Authentication', estado: det(credStuffing.length + cov.auth.length, 'alta'),
      severidad: credStuffing.some((b) => b.severidad === 'alta') || cov.auth.some((h) => h.severidad === 'alta') ? 'alta' : (credStuffing.length + cov.auth.length) ? 'media' : 'baja',
      count: credStuffing.length + cov.auth.length,
      evidencia: [
        ...credStuffing.slice(0, 4).map((b) => `${b.source}${b.pais ? ` (${b.pais})` : ''} -> ${b.target}:${b.topPort} (${b.flows} flujos)`),
        ...cov.auth.slice(0, 4).map((h) => h.titulo),
      ],
      fuente: cov.cobertura ? `DDoS/Bots (SonicWall) + ${fuenteHttp}` : 'DDoS/Bots (SonicWall)', ruta: cov.auth.length ? '/analitica-api' : '/ddos',
      descripcion: 'Credential stuffing / ATO a nivel red (puertos web/API) + fallos de autenticación (401/403) por endpoint.',
    },
    SINCOB('API3', 'Broken Object Property Level Authorization', 'Exposición/modificación de propiedades de objetos no autorizadas. Requiere inspección del payload.'),
    {
      id: 'API4', nombre: 'Unrestricted Resource Consumption', estado: det(volum.length + httpFlood.length, 'alta'),
      severidad: volum.some((v) => v.severidad === 'alta') ? 'alta' : (volum.length + httpFlood.length) ? 'media' : 'baja',
      count: volum.length + httpFlood.length,
      evidencia: [...volum.slice(0, 4).map((v) => `${v.tipo} -> ${v.target} (${v.sources} orígenes, ${v.flows} flujos)`),
        ...httpFlood.slice(0, 2).map((b) => `http-flood ${b.source} -> ${b.target} (${b.flows})`)],
      fuente: 'DDoS/Bots (SonicWall)', ruta: '/ddos',
      descripcion: 'API DDoS / HTTP flood: saturación de recursos (fan-in, amplificación, flood).',
    },
    cov.cobertura
      ? {
          id: 'API5', nombre: 'Broken Function Level Authorization', estado: cov.funcion.length ? 'detectado' : 'limpio',
          severidad: cov.funcion.some((h) => h.severidad === 'alta') ? 'alta' : cov.funcion.length ? 'media' : 'baja',
          count: cov.funcion.length,
          evidencia: cov.funcion.slice(0, 6).map((h) => h.titulo),
          fuente: fuenteHttp, ruta: '/analitica-api',
          descripcion: 'Intentos de acceder a funciones/recursos privilegiados (respuestas 403) sin autorización de nivel. Observable por analítica de logs HTTP por endpoint.',
        }
      : SINCOB('API5', 'Broken Function Level Authorization', 'Acceso a funciones/administración no autorizadas. Requiere analítica por endpoint y rol.'),
    {
      id: 'API6', nombre: 'Unrestricted Access to Sensitive Business Flows', estado: det(scraping.length, 'media'),
      severidad: scraping.length ? 'media' : 'baja', count: scraping.length,
      evidencia: scraping.slice(0, 6).map((b) => `${b.source}${b.pais ? ` (${b.pais})` : ''} -> ${b.target}:${b.topPort} (${b.flows} flujos)`),
      fuente: 'DDoS/Bots (SonicWall)', ruta: '/ddos',
      descripcion: 'Scraping / abuso automatizado de flujos de negocio por bots.',
    },
    {
      id: 'API7', nombre: 'Server Side Request Forgery (SSRF)', estado: 'limpio', severidad: 'info', count: 0,
      evidencia: [], fuente: 'Monitoreado por Flujos de red / beaconing', ruta: '/flows',
      descripcion: 'Peticiones forzadas desde el servidor a destinos internos/metadata. Monitoreado por anomalías de flujo saliente; sin señal confirmada en el rango.',
    },
    {
      id: 'API8', nombre: 'Security Misconfiguration', estado: det(specs.length, 'alta'),
      severidad: specs.length ? 'alta' : 'baja', count: specs.length,
      evidencia: specs.slice(0, 6).flatMap((e) => e.hallazgos.map((h) => `${e.host}: ${h.titulo}`)),
      fuente: 'Exposición de APIs (ASM)', ruta: '/exposicion-apis',
      descripcion: 'Specs/documentación expuesta (Swagger/OpenAPI, introspección GraphQL, Actuator) que revela la estructura de la API.',
    },
    {
      id: 'API9', nombre: 'Improper Inventory Management', estado: det(shadowZombie, 'media'),
      severidad: shadowZombie ? 'media' : 'baja', count: shadowZombie,
      evidencia: [
        ...(exp.resumen.nuevos ? [`${exp.resumen.nuevos} API(s) nueva(s)/shadow`] : []),
        ...(exp.resumen.zombies ? [`${exp.resumen.zombies} API(s) zombie (dejaron de responder)`] : []),
        `${exp.resumen.apis} API(s) en inventario`,
      ],
      fuente: 'Exposición de APIs (ASM)', ruta: '/exposicion-apis',
      descripcion: 'APIs shadow (no documentadas) y zombie (obsoletas) en la superficie expuesta.',
    },
    SINCOB('API10', 'Unsafe Consumption of APIs', 'Confianza excesiva en APIs de terceros que consume la app del cliente. No observable desde el perímetro.'),
  ];

  const resumen = {
    detectadas: categorias.filter((c) => c.estado === 'detectado').length,
    limpias: categorias.filter((c) => c.estado === 'limpio').length,
    sinCobertura: categorias.filter((c) => c.estado === 'sin-cobertura').length,
  };
  return { range, generadoEn: new Date().toISOString(), resumen, categorias };
}

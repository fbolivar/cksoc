/**
 * UEBA — analítica de comportamiento de usuarios/entidades.
 *
 * El motor construye una LÍNEA BASE por usuario a partir de los eventos de
 * autenticación (hosts a los que suele entrar, si trabaja en horario laboral,
 * países desde los que se conecta) sobre una ventana amplia, y luego revisa la
 * ventana reciente buscando DESVIACIONES:
 *   - new_host            → entra a una máquina fuera de su patrón (lateral)
 *   - off_hours           → inicia sesión fuera de su horario habitual
 *   - auth_failure_spike  → ráfaga de fallos de autenticación (fuerza bruta/spray)
 *   - impossible_travel   → dos logins con geo cuya velocidad implícita es > umbral
 *   - new_country         → login desde un país nunca visto en su línea base
 *
 * Es AGNÓSTICO DE LA FUENTE: hoy consume los logins de Wazuh (auth interna). Los
 * detectores geográficos (impossible_travel / new_country) sólo disparan cuando
 * hay logins con IP pública + geo — hoy casi nulos en Wazuh, se encienden solos
 * cuando lleguen los sign-in de Microsoft 365 (misma tubería, `collectLogins`).
 */
import { query } from '../../config/db';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { geolocate, isPublicIP, type GeoLocation } from '../geo/geoip.service';
import { env } from '../../config/env';
import { logger } from '../../config/logger';

// ---------------------------------------------------------------------------
// Configuración
// ---------------------------------------------------------------------------

export interface UebaSettings {
  biz_start_hour: number;
  biz_end_hour: number;
  include_weekend: boolean;
  lookback_days: number;
  recent_hours: number;
  fail_threshold: number;
  impossible_kmh: number;
}

const DEFAULTS: UebaSettings = {
  biz_start_hour: 6, biz_end_hour: 21, include_weekend: false,
  lookback_days: 30, recent_hours: 24, fail_threshold: 8, impossible_kmh: 900,
};

export async function getSettings(): Promise<UebaSettings> {
  const rows = await query<UebaSettings>('SELECT biz_start_hour, biz_end_hour, include_weekend, lookback_days, recent_hours, fail_threshold, impossible_kmh FROM ueba_settings WHERE id = TRUE');
  return rows[0] ?? DEFAULTS;
}

export async function updateSettings(input: Partial<UebaSettings>): Promise<UebaSettings> {
  const cur = await getSettings();
  const n = (v: unknown, def: number, min: number, max: number) => Math.min(Math.max(Math.round(Number(v ?? def)), min), max);
  const s: UebaSettings = {
    biz_start_hour: n(input.biz_start_hour, cur.biz_start_hour, 0, 23),
    biz_end_hour: n(input.biz_end_hour, cur.biz_end_hour, 1, 24),
    include_weekend: input.include_weekend ?? cur.include_weekend,
    lookback_days: n(input.lookback_days, cur.lookback_days, 7, 90),
    recent_hours: n(input.recent_hours, cur.recent_hours, 1, 168),
    fail_threshold: n(input.fail_threshold, cur.fail_threshold, 3, 100),
    impossible_kmh: n(input.impossible_kmh, cur.impossible_kmh, 300, 3000),
  };
  if (s.biz_end_hour <= s.biz_start_hour) s.biz_end_hour = Math.min(23, s.biz_start_hour + 1);
  await query(
    `UPDATE ueba_settings SET biz_start_hour=$1, biz_end_hour=$2, include_weekend=$3, lookback_days=$4, recent_hours=$5, fail_threshold=$6, impossible_kmh=$7, updated_at=now() WHERE id = TRUE`,
    [s.biz_start_hour, s.biz_end_hour, s.include_weekend, s.lookback_days, s.recent_hours, s.fail_threshold, s.impossible_kmh]
  );
  return s;
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

/** Colombia es UTC-5 fijo (sin horario de verano). */
const CO_OFFSET_MS = 5 * 3600 * 1000;

/** Hora (0-23) y día de la semana (0=Dom..6=Sáb) en hora local de Colombia. */
function localParts(iso: string): { hour: number; dow: number } {
  const d = new Date(new Date(iso).getTime() - CO_OFFSET_MS);
  return { hour: d.getUTCHours(), dow: d.getUTCDay() };
}

/** ¿El evento cae fuera del horario laboral configurado? */
function isOffHours(iso: string, s: UebaSettings): boolean {
  const { hour, dow } = localParts(iso);
  const weekend = dow === 0 || dow === 6;
  if (weekend && !s.include_weekend) return true;
  return hour < s.biz_start_hour || hour >= s.biz_end_hour;
}

/** Distancia entre dos coordenadas en km (haversine). */
function haversineKm(a: GeoLocation, b: GeoLocation): number {
  const R = 6371;
  const toRad = (x: number) => (x * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const lat1 = toRad(a.lat), lat2 = toRad(b.lat);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

/** Cuentas de máquina/servicio que no son "usuarios" reales para UEBA. */
const IGNORE_USERS = new Set(['', '-', 'anonymous logon', 'system', 'local service', 'network service']);
function cleanUser(u: unknown): string | null {
  const s = String(u ?? '').trim();
  if (!s) return null;
  const low = s.toLowerCase();
  if (IGNORE_USERS.has(low)) return null;
  if (s.endsWith('$')) return null;                 // cuenta de equipo Windows
  if (/^(dwm|umfd)-\d+$/i.test(s)) return null;      // sesiones del sistema
  return s;
}

/**
 * Cuentas de SERVICIO y ADMINISTRACIÓN: no son "usuarios" a vigilar por UEBA.
 * Un admin inicia sesión a cualquier hora y entra a muchas máquinas por su trabajo;
 * una cuenta de servicio corre 24/7 y los findes. Marcarlas genera puro falso
 * positivo. UEBA debe vigilar a los EMPLEADOS reales (nombres de persona), así que
 * estas se excluyen de las anomalías. Editar aquí para ampliar la lista.
 */
const EXCLUDE_ENTITY_RE = /^(?:soporte|fernando[.\s]?bolivar|admin(?:istrator|istrador)?|root|sistema|system|guest|invitado|hexdesk|backup|gvm.*|svc[-_.].*|hp|usuario|user|postgres|velociraptor|wazuh|syslog|fboli.*|dwm[-_].*|umfd[-_].*)$/i;
/** ¿La entidad es una cuenta de servicio/admin/genérica (no un empleado real)?
 *  Reutilizada por UEBA y por Riesgo por entidad para no priorizar admins/robots. */
export function isServiceOrAdmin(entity: string): boolean {
  return EXCLUDE_ENTITY_RE.test(String(entity).trim());
}

const SUCCESS_GROUP = 'authentication_success';
const FAIL_GROUPS = ['authentication_failed', 'win_authentication_failed'];
// Rule 67022 "Non network or service local logon" llega por WEF en el grupo
// `windows` (no en authentication_success): sin esto UEBA era ciego a los logons
// interactivos reales de los empleados. Se clasifica como exito (no esta en FAIL_GROUPS).
const SUCCESS_RULE_IDS = ['67022'];
const USER_FIELDS = ['data.srcuser', 'data.dstuser', 'data.win.eventdata.targetUserName'];

// Painless: ¿el @timestamp del doc cae fuera del horario laboral (hora Colombia)?
// Nota: en el painless del Indexer (OpenSearch) getDayOfWeek() ya devuelve un
// entero 1-7 (lun-dom); NO lleva .getValue() — eso lanzaría un error de runtime.
const OFF_HOURS_SCRIPT =
  "int h = doc['@timestamp'].value.getHour(); int lh = ((h - 5) % 24 + 24) % 24;" +
  " int dow = doc['@timestamp'].value.getDayOfWeek();" +
  " boolean weekend = dow >= 6; if (weekend && !params.wknd) return true;" +
  " return lh < params.s || lh >= params.e;";

// ---------------------------------------------------------------------------
// Recolección de logins (fuente: Wazuh; extensible a M365)
// ---------------------------------------------------------------------------

export interface LoginEvent {
  ts: string;
  user: string;
  host: string;
  srcip: string | null;
  outcome: 'success' | 'fail';
  source: 'wazuh' | 'm365';
  geo: GeoLocation | null;
}

interface RawHit {
  _source: {
    '@timestamp'?: string;
    rule?: { groups?: string[] };
    agent?: { name?: string };
    data?: {
      srcuser?: string; dstuser?: string; srcip?: string;
      win?: { eventdata?: { targetUserName?: string; ipAddress?: string } };
    };
  };
}

function normalizeHit(h: RawHit): LoginEvent | null {
  const s = h._source;
  const user = cleanUser(s.data?.srcuser) ?? cleanUser(s.data?.dstuser) ?? cleanUser(s.data?.win?.eventdata?.targetUserName);
  if (!user) return null;
  const ts = s['@timestamp'];
  if (!ts) return null;
  const groups = s.rule?.groups ?? [];
  const outcome: 'success' | 'fail' = groups.some((g) => FAIL_GROUPS.includes(g)) ? 'fail' : 'success';
  const rawIp = s.data?.srcip || s.data?.win?.eventdata?.ipAddress || null;
  const srcip = rawIp && isPublicIP(rawIp) ? rawIp : null;
  return {
    ts, user, host: s.agent?.name ?? '(desconocido)', srcip, outcome,
    source: 'wazuh', geo: srcip ? geolocate(srcip) : null,
  };
}

/**
 * Logins de la ventana reciente (crudos, se normalizan en JS). Incluye éxitos y
 * fallos. Punto de extensión: aquí se unirán los sign-in de Microsoft 365.
 */
export async function collectLogins(hours: number): Promise<LoginEvent[]> {
  const client = getIndexerClient();
  const { data } = await client.post<{ hits?: { hits?: RawHit[] } }>(
    `/${env.WAZUH_ALERTS_INDEX}/_search`,
    {
      size: 5000,
      _source: ['@timestamp', 'rule.groups', 'agent.name', 'data.srcuser', 'data.dstuser', 'data.srcip', 'data.win.eventdata.targetUserName', 'data.win.eventdata.ipAddress'],
      query: { bool: {
        filter: [
          { range: { '@timestamp': { gte: `now-${hours}h` } } },
          { bool: { should: [
            { terms: { 'rule.groups': [SUCCESS_GROUP, ...FAIL_GROUPS] } },
            { terms: { 'rule.id': SUCCESS_RULE_IDS } },
          ], minimum_should_match: 1 } },
        ],
        // Excluir el FP masivo de SMB en red SIN dominio: 4625 con subStatus
        // 0xC0000064 = "el usuario no existe" (una estación pide un recurso con su
        // cuenta local; el servidor no la conoce). No es fuerza bruta. El spraying
        // REAL usa 0xC000006A (contraseña incorrecta sobre usuario existente) y sí
        // se conserva. Esto limpia el detector auth_failure_spike de UEBA.
        must_not: [{ term: { 'data.win.eventdata.subStatus': '0xc0000064' } }],
      } },
      sort: [{ '@timestamp': { order: 'asc' } }],
    }
  );
  const out: LoginEvent[] = [];
  for (const h of data.hits?.hits ?? []) {
    const e = normalizeHit(h);
    if (e) out.push(e);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Línea base por usuario
// ---------------------------------------------------------------------------

export interface UserBaseline {
  hosts: Set<string>;
  countries: Set<string>;
  total: number;
  off: number;
}

interface TermsAgg { buckets: { key: string; doc_count: number; hosts: { buckets: { key: string }[] }; off: { doc_count: number } }[] }

/**
 * Construye la línea base agregando por cada campo de usuario posible y
 * fusionando. Devuelve, por usuario: hosts habituales, ratio de actividad
 * fuera de horario y (cuando la fuente tiene geo) países vistos.
 */
export async function buildBaseline(s: UebaSettings): Promise<Map<string, UserBaseline>> {
  const client = getIndexerClient();
  const map = new Map<string, UserBaseline>();
  const params = { s: s.biz_start_hour, e: s.biz_end_hour, wknd: s.include_weekend };

  for (const field of USER_FIELDS) {
    const { data } = await client.post<{ aggregations?: { u: TermsAgg } }>(
      `/${env.WAZUH_ALERTS_INDEX}/_search`,
      {
        size: 0,
        query: { bool: { filter: [
          { range: { '@timestamp': { gte: `now-${s.lookback_days}d`, lt: 'now-1d' } } },
          { bool: { should: [
            { term: { 'rule.groups': SUCCESS_GROUP } },
            { terms: { 'rule.id': SUCCESS_RULE_IDS } },
          ], minimum_should_match: 1 } },
          { exists: { field } },
        ] } },
        aggs: {
          u: {
            terms: { field, size: 1000 },
            aggs: {
              hosts: { terms: { field: 'agent.name', size: 60 } },
              off: { filter: { script: { script: { source: OFF_HOURS_SCRIPT, params, lang: 'painless' } } } },
            },
          },
        },
      }
    );
    for (const b of data.aggregations?.u?.buckets ?? []) {
      const user = cleanUser(b.key);
      if (!user) continue;
      const cur = map.get(user) ?? { hosts: new Set<string>(), countries: new Set<string>(), total: 0, off: 0 };
      for (const hb of b.hosts.buckets) cur.hosts.add(hb.key);
      cur.total += b.doc_count;
      cur.off += b.off.doc_count;
      map.set(user, cur);
    }
  }
  return map;
}

// ---------------------------------------------------------------------------
// Detectores
// ---------------------------------------------------------------------------

export type Detector = 'new_host' | 'off_hours' | 'auth_failure_spike' | 'impossible_travel' | 'new_country';
type Severity = 'baja' | 'media' | 'alta' | 'critica';

interface Anomaly {
  detector: Detector;
  entity: string;
  severity: Severity;
  score: number;
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  source: 'wazuh' | 'm365';
  dedupKey: string;
}

/** Discriminador diario (hora Colombia) para no duplicar la misma anomalía. */
function dayKey(iso: string): string {
  const d = new Date(new Date(iso).getTime() - CO_OFFSET_MS);
  return d.toISOString().slice(0, 10);
}

function detect(logins: LoginEvent[], baseline: Map<string, UserBaseline>, s: UebaSettings): Anomaly[] {
  const anomalies: Anomaly[] = [];
  const successByUser = new Map<string, LoginEvent[]>();
  const failByUser = new Map<string, LoginEvent[]>();

  for (const e of logins) {
    const bucket = e.outcome === 'success' ? successByUser : failByUser;
    const arr = bucket.get(e.user) ?? [];
    arr.push(e);
    bucket.set(e.user, arr);
  }

  // --- new_host & off_hours (requieren usuario con línea base conocida) ---
  const seenNewHost = new Set<string>();
  const seenOffHours = new Set<string>();
  for (const [user, events] of successByUser) {
    const base = baseline.get(user);
    if (!base || base.total < 5) continue; // sin historial suficiente no hay "normal"

    for (const e of events) {
      // Host nuevo
      if (!base.hosts.has(e.host)) {
        const k = `new_host|${user}|${e.host}`;
        if (!seenNewHost.has(k)) {
          seenNewHost.add(k);
          anomalies.push({
            detector: 'new_host', entity: user, severity: 'media', score: 45,
            title: `${user} accedió a un host fuera de su patrón: ${e.host}`,
            summary: `El usuario ${user} inició sesión en ${e.host}, una máquina que no aparece en sus ${base.hosts.size} hosts habituales de los últimos ${s.lookback_days} días. Posible movimiento lateral o uso de credenciales robadas.`,
            evidence: { host: e.host, ts: e.ts, srcip: e.srcip, usualHosts: [...base.hosts].slice(0, 12) },
            source: e.source, dedupKey: `${k}|${dayKey(e.ts)}`,
          });
        }
      }
      // Fuera de horario (sólo si el usuario normalmente trabaja en horario)
      if (isOffHours(e.ts, s)) {
        const offRatio = base.total > 0 ? base.off / base.total : 1;
        if (offRatio < 0.15) {
          const k = `off_hours|${user}`;
          if (!seenOffHours.has(k + dayKey(e.ts))) {
            seenOffHours.add(k + dayKey(e.ts));
            const { hour, dow } = localParts(e.ts);
            const hh = String(hour).padStart(2, '0');
            const finde = dow === 0 || dow === 6;
            const diaFinde = dow === 6 ? 'sábado' : 'domingo';
            const motivo = finde ? `${diaFinde} ${hh}:00 · fin de semana` : `${hh}:00, hora Colombia`;
            anomalies.push({
              detector: 'off_hours', entity: user, severity: 'media', score: 35,
              title: `${user} inició sesión fuera de horario (${motivo})`,
              summary: `El usuario ${user} normalmente trabaja en horario laboral, pero inició sesión ${finde ? `un ${diaFinde} a las ${hh}:00` : `a las ${hh}:00`} en ${e.host}. Horario laboral configurado: ${String(s.biz_start_hour).padStart(2, '0')}:00–${String(s.biz_end_hour).padStart(2, '0')}:00, ${s.include_weekend ? 'incluye' : 'sin'} fines de semana.`,
              evidence: { ts: e.ts, host: e.host, hour, weekend: finde, srcip: e.srcip, baselineOffRatio: Number(offRatio.toFixed(3)) },
              source: e.source, dedupKey: `${k}|${dayKey(e.ts)}`,
            });
          }
        }
      }
    }
  }

  // --- auth_failure_spike (por usuario) ---
  // Distingue ataques de RED (con IP de origen pública -> fuerza bruta/spray real)
  // de fallos LOCALES/interactivos sin IP (típicamente errores de contraseña al
  // iniciar/desbloquear sesión). Solo los de red son "alta"; los locales se degradan
  // a "media" y exigen el DOBLE de umbral, para no inundar el panel con falsas
  // "altas" benignas (typos repartidos entre muchos usuarios/estaciones).
  for (const [user, fails] of failByUser) {
    if (fails.length < s.fail_threshold) continue;
    const hosts = [...new Set(fails.map((f) => f.host))];
    const netFails = fails.filter((f) => f.srcip);
    const ips = [...new Set(netFails.map((f) => f.srcip))].filter(Boolean) as string[];
    const network = netFails.length >= s.fail_threshold;
    // Local puro (sin IP): solo se reporta si dobla el umbral, y como "media".
    if (!network && fails.length < s.fail_threshold * 2) continue;
    anomalies.push({
      detector: 'auth_failure_spike', entity: user,
      severity: network ? 'alta' : 'media',
      score: (network ? 60 : 35) + Math.min(30, fails.length),
      title: `Ráfaga de fallos de autenticación para ${user} (${fails.length})`,
      summary: network
        ? `Se registraron ${netFails.length} fallos de autenticación DESDE RED para ${user} (IP: ${ips.slice(0, 5).join(', ')}) en las últimas ${s.recent_hours} h sobre ${hosts.length} host(s). Posible fuerza bruta o password spraying.`
        : `Se registraron ${fails.length} fallos de inicio de sesión LOCAL para ${user} en las últimas ${s.recent_hours} h sobre ${hosts.length} host(s), sin IP de origen. Probables errores de contraseña al iniciar/desbloquear; revisar si persiste o se concentra en una cuenta.`,
      evidence: { count: fails.length, networkFails: netFails.length, ips: ips.slice(0, 12), hosts: hosts.slice(0, 12), firstTs: fails[0].ts, lastTs: fails[fails.length - 1].ts },
      source: fails[0].source, dedupKey: `auth_failure_spike|${user}|${dayKey(fails[fails.length - 1].ts)}`,
    });
  }

  // --- impossible_travel & new_country (geo; hoy ~0 en Wazuh, listos para M365) ---
  for (const [user, events] of successByUser) {
    const geoEvents = events.filter((e) => e.geo).sort((a, b) => a.ts.localeCompare(b.ts));
    if (geoEvents.length === 0) continue;
    const base = baseline.get(user);

    // País nuevo
    if (base && base.countries.size > 0) {
      for (const e of geoEvents) {
        const c = e.geo!.isoCode || e.geo!.country;
        if (c && !base.countries.has(c)) {
          anomalies.push({
            detector: 'new_country', entity: user, severity: 'alta', score: 70,
            title: `${user} inició sesión desde un país nuevo: ${e.geo!.country}`,
            summary: `El usuario ${user} se conectó desde ${e.geo!.city ? e.geo!.city + ', ' : ''}${e.geo!.country} (${e.srcip}), un país que no aparece en su línea base.`,
            evidence: { ts: e.ts, srcip: e.srcip, geo: e.geo, usualCountries: [...base.countries].slice(0, 12) },
            source: e.source, dedupKey: `new_country|${user}|${c}|${dayKey(e.ts)}`,
          });
        }
      }
    }

    // Viaje imposible: pares consecutivos
    for (let i = 1; i < geoEvents.length; i++) {
      const a = geoEvents[i - 1], b = geoEvents[i];
      const km = haversineKm(a.geo!, b.geo!);
      const hoursDiff = (new Date(b.ts).getTime() - new Date(a.ts).getTime()) / 3600000;
      if (km < 400 || hoursDiff <= 0) continue; // misma ciudad o sin salto temporal
      const kmh = km / hoursDiff;
      if (kmh > s.impossible_kmh) {
        anomalies.push({
          detector: 'impossible_travel', entity: user, severity: 'critica', score: 90,
          title: `Viaje imposible para ${user}: ${a.geo!.city || a.geo!.country} → ${b.geo!.city || b.geo!.country}`,
          summary: `${user} inició sesión desde ${a.geo!.country} y ${Math.round(hoursDiff * 60)} min después desde ${b.geo!.country} (${Math.round(km)} km, ${Math.round(kmh)} km/h implícitos). Físicamente imposible → una de las dos sesiones probablemente no es el usuario.`,
          evidence: { from: { srcip: a.srcip, geo: a.geo, ts: a.ts }, to: { srcip: b.srcip, geo: b.geo, ts: b.ts }, km: Math.round(km), kmh: Math.round(kmh) },
          source: b.source, dedupKey: `impossible_travel|${user}|${a.geo!.isoCode}-${b.geo!.isoCode}|${dayKey(b.ts)}`,
        });
      }
    }
  }

  // UEBA vigila EMPLEADOS, no cuentas de servicio/admin: se descartan sus anomalías.
  return anomalies.filter((a) => !isServiceOrAdmin(a.entity));
}

// ---------------------------------------------------------------------------
// Persistencia + motor
// ---------------------------------------------------------------------------

async function persist(anomalies: Anomaly[]): Promise<number> {
  let n = 0;
  for (const a of anomalies) {
    await query(
      `INSERT INTO ueba_anomalies (detector, entity, severity, score, title, summary, evidence, source, dedup_key)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
       ON CONFLICT (dedup_key) DO UPDATE
         SET last_seen = now(),
             score = GREATEST(ueba_anomalies.score, EXCLUDED.score),
             evidence = EXCLUDED.evidence,
             severity = EXCLUDED.severity`,
      [a.detector, a.entity, a.severity, a.score, a.title, a.summary, JSON.stringify(a.evidence), a.source, a.dedupKey]
    );
    n++;
  }
  return n;
}

export interface ScanResult { logins: number; users: number; anomalies: number; byDetector: Record<string, number>; }

/** Corre un ciclo completo: línea base → recolección → detección → persistencia. */
export async function scan(): Promise<ScanResult> {
  const s = await getSettings();
  const [baseline, logins] = await Promise.all([buildBaseline(s), collectLogins(s.recent_hours)]);
  const anomalies = detect(logins, baseline, s);
  await persist(anomalies);
  const byDetector: Record<string, number> = {};
  for (const a of anomalies) byDetector[a.detector] = (byDetector[a.detector] ?? 0) + 1;
  logger.info({ logins: logins.length, users: baseline.size, anomalies: anomalies.length, byDetector }, 'UEBA: escaneo completado');
  return { logins: logins.length, users: baseline.size, anomalies: anomalies.length, byDetector };
}

// ---------------------------------------------------------------------------
// Consulta / gestión de anomalías
// ---------------------------------------------------------------------------

export interface AnomalyRow {
  id: string; detector: Detector; entity: string; entity_type: string;
  severity: Severity; score: number; title: string; summary: string;
  evidence: Record<string, unknown>; source: string; status: string;
  first_seen: string; last_seen: string; ack_by: string | null; ack_at: string | null;
}

export async function listAnomalies(opts: { status?: string; detector?: string; days?: number } = {}): Promise<AnomalyRow[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.status && opts.status !== 'all') { params.push(opts.status); where.push(`status = $${params.length}`); }
  if (opts.detector) { params.push(opts.detector); where.push(`detector = $${params.length}`); }
  const days = Math.min(Math.max(opts.days ?? 14, 1), 90);
  params.push(days);
  where.push(`last_seen > now() - ($${params.length} || ' days')::interval`);
  const sql = `SELECT id, detector, entity, entity_type, severity, score, title, summary, evidence, source, status, first_seen, last_seen, ack_by, ack_at
               FROM ueba_anomalies ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
               ORDER BY (status = 'open') DESC, score DESC, last_seen DESC LIMIT 400`;
  return query<AnomalyRow>(sql, params);
}

export async function countOpen(): Promise<number> {
  const r = await query<{ n: string }>("SELECT COUNT(*)::int AS n FROM ueba_anomalies WHERE status = 'open'");
  return Number(r[0]?.n ?? 0);
}

export async function setStatus(id: string, status: 'open' | 'ack' | 'dismissed', userId: string): Promise<AnomalyRow> {
  const rows = await query<AnomalyRow>(
    `UPDATE ueba_anomalies SET status = $2, ack_by = CASE WHEN $2 = 'open' THEN NULL ELSE $3 END,
       ack_at = CASE WHEN $2 = 'open' THEN NULL ELSE now() END WHERE id = $1
     RETURNING id, detector, entity, entity_type, severity, score, title, summary, evidence, source, status, first_seen, last_seen, ack_by, ack_at`,
    [id, status, userId]
  );
  return rows[0];
}

/** Perfil de comportamiento de un usuario (línea base + anomalías recientes). */
export async function entityProfile(user: string): Promise<{ user: string; baseline: { hosts: string[]; countries: string[]; total: number; offRatio: number } | null; anomalies: AnomalyRow[] }> {
  const s = await getSettings();
  const baseline = await buildBaseline(s);
  const b = baseline.get(user) ?? null;
  const anomalies = await query<AnomalyRow>(
    `SELECT id, detector, entity, entity_type, severity, score, title, summary, evidence, source, status, first_seen, last_seen, ack_by, ack_at
     FROM ueba_anomalies WHERE entity = $1 ORDER BY last_seen DESC LIMIT 100`, [user]
  );
  return {
    user,
    baseline: b ? { hosts: [...b.hosts], countries: [...b.countries], total: b.total, offRatio: b.total ? Number((b.off / b.total).toFixed(3)) : 0 } : null,
    anomalies,
  };
}

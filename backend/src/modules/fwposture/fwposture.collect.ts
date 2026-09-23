/**
 * Recolección de postura del SonicWall (SOLO LECTURA) para el reporte de seguridad.
 * Lee versión, interfaces, reglas de acceso, usuarios locales y SNMP vía la API
 * SonicOS (/api/sonicos) y arma un "snapshot" SANITIZADO (sin secretos: contraseñas,
 * llaves, psk) apto para evaluar con checks deterministas y para el análisis con IA.
 *
 * NOTA de portabilidad: SonicOS no expone un endpoint de "administration" por API en
 * este firmware (7.3.x devuelve 400), por lo que los ajustes globales de administración
 * (timeout, telnet, lockout, strong-crypto) quedan sin dato → esos checks salen "na".
 * Tampoco existe "Security Rating" nativo ni trusted-hosts por usuario (el origen de la
 * gestión se controla a nivel de interfaz/zona, que sí evaluamos en el check WAN-mgmt).
 */
import { fgGet } from '../response/fortigate.service';
import { logger } from '../../config/logger';

export interface FwAdmin { name: string; profile: string; twoFactor: string; trusthostOpen: boolean; sshKey: boolean; }
export interface FwPolicy { id: number; name: string; action: string; anyAny: boolean; log: boolean; utm: boolean; }
export interface FwIface { name: string; alias: string | null; role: string | null; allowaccess: string; wan: boolean; }

export interface FwSnapshot {
  device: { hostname: string; model: string; serial: string; version: string; build: string | number };
  securityRating: unknown | null;   // SonicOS no tiene equivalente nativo → null
  global: Record<string, unknown>;  // ajustes clave (sanitizados); vacío en SonicOS (sin API de administration)
  admins: FwAdmin[];
  interfaces: FwIface[];
  policies: { total: number; enabled: number; anyAnyAccept: number; sinLog: number; sinUtmAccept: number; items: FwPolicy[] };
  snmpCommunities: number;          // comunidades SNMP v1/v2c activas
  fortiguard: Record<string, unknown> | null;
  collectedAt: string;
}

// ---- Formas (parciales) de la API SonicOS que consumimos ----
interface SwVersion { firmware_version?: string; rom_version?: string; model?: string; serial_number?: string; }
interface SwMgmt { https?: boolean; ssh?: boolean; ping?: boolean; snmp?: boolean }
interface SwIfaceRow { ipv4?: { name?: string; comment?: string; ip_assignment?: { zone?: string }; management?: SwMgmt; user_login?: { http?: boolean; https?: boolean } } }
interface SwAddr { any?: boolean; name?: string; group?: string }
interface SwRuleRow { ipv4?: { name?: string; action?: string; enable?: boolean; logging?: boolean; source?: { address?: SwAddr }; destination?: { address?: SwAddr }; service?: { any?: boolean; name?: string; group?: string } } }
interface SwUser { name?: string; comment?: string; one_time_password?: Record<string, unknown>; member_of?: { name?: string }[] }
interface SwSnmp { enable?: boolean; get_community_name?: string; snmp3?: { mandatory?: boolean } }

async function safe<T>(path: string, fallback: T): Promise<T> {
  try { return await fgGet<T>(path); } catch (err) { logger.warn({ err: err instanceof Error ? err.message : err, path }, 'fwposture: fallo al leer'); return fallback; }
}

/** ¿El grupo denota rol administrativo del appliance? (no VPN/usuarios normales) */
const isAdminGroup = (name: string): boolean => /administrator/i.test(name);

export async function collectFwSnapshot(): Promise<FwSnapshot> {
  // SonicOS admite UNA sola sesion de gestion: las lecturas van EN SERIE (no Promise.all),
  // si no, los auth por cookie concurrentes se invalidan entre si y todo devuelve vacio.
  const ver = await safe<SwVersion>('/version', {});
  const ifacesR = await safe<{ interfaces?: SwIfaceRow[] }>('/interfaces/ipv4', { interfaces: [] });
  const rulesR = await safe<{ access_rules?: SwRuleRow[] }>('/access-rules/ipv4', { access_rules: [] });
  const usersR = await safe<{ user?: { local?: { user?: SwUser[] } } }>('/user/local/users', { user: { local: { user: [] } } });
  const snmpR = await safe<{ snmp?: SwSnmp }>('/snmp/base', { snmp: {} });

  // --- Administradores del appliance (miembros de un grupo *Administrators*) ---
  const localUsers = usersR.user?.local?.user ?? [];
  const admins: FwAdmin[] = localUsers
    .filter((u) => (u.member_of ?? []).some((m) => isAdminGroup(String(m?.name ?? ''))))
    .map((u) => ({
      name: String(u.name ?? ''),
      profile: (u.member_of ?? []).map((m) => String(m?.name ?? '')).find(isAdminGroup) ?? '',
      // OTP configurado (objeto no vacío) => 2FA activo.
      twoFactor: Object.keys(u.one_time_password ?? {}).length > 0 ? 'enable' : 'disable',
      // SonicOS no tiene trusted-hosts por usuario; el origen de gestión se controla por
      // interfaz/zona (evaluado en el check WAN-mgmt), así que no marcamos "abierto" aquí.
      trusthostOpen: false,
      sshKey: false,
    }));

  // --- Interfaces: allowaccess derivado de management + user_login; wan por zona ---
  const interfaces: FwIface[] = (ifacesR.interfaces ?? []).map((row) => {
    const i = row.ipv4 ?? {};
    const zone = String(i.ip_assignment?.zone ?? '');
    const m = i.management ?? {};
    const ul = i.user_login ?? {};
    const acc: string[] = [];
    if (m.https) acc.push('https');
    if (m.ssh) acc.push('ssh');
    if (ul.http) acc.push('http');
    if (m.ping) acc.push('ping');
    if (m.snmp) acc.push('snmp');
    return {
      name: String(i.name ?? ''),
      alias: i.comment ? String(i.comment) : null,
      role: zone || null,
      allowaccess: acc.join(' '),
      wan: zone.toUpperCase() === 'WAN',
    };
  }).filter((i) => i.name);

  // --- Reglas de acceso (SonicOS "allow" ≈ FortiOS "accept") ---
  const rules = rulesR.access_rules ?? [];
  const items: FwPolicy[] = rules.map((row, idx) => {
    const r = row.ipv4 ?? {};
    const action = String(r.action ?? '') === 'allow' ? 'accept' : String(r.action ?? '');
    const anyAny = Boolean(r.source?.address?.any) && Boolean(r.destination?.address?.any) && Boolean(r.service?.any);
    const log = Boolean(r.logging);
    // SonicOS aplica los Servicios de Seguridad (GAV/IPS/App Control/CFS/DPI-SSL) a nivel
    // de motor/zona, no como perfil por regla → no hay "regla accept sin UTM" en SonicOS.
    const utm = true;
    return { id: idx + 1, name: String(r.name ?? ''), action, anyAny, log, utm };
  });
  const accept = items.filter((p) => p.action === 'accept');

  // --- SNMP v1/v2c: comunidad activa solo si SNMP habilitado y v3 no obligatorio ---
  const snmp = snmpR.snmp ?? {};
  const snmpCommunities = snmp.enable && !snmp.snmp3?.mandatory && String(snmp.get_community_name ?? '').trim() ? 1 : 0;

  const model = String(ver.model ?? '');

  return {
    device: {
      hostname: (model ? `SonicWall ${model}` : 'SonicWall').trim(),
      model,
      serial: String(ver.serial_number ?? ''),
      version: String(ver.firmware_version ?? ''),
      build: String(ver.rom_version ?? ''),
    },
    securityRating: null,
    global: {}, // SonicOS: sin API de administration → checks globales quedan "na"
    admins,
    interfaces,
    policies: {
      total: items.length,
      enabled: items.length,
      anyAnyAccept: accept.filter((p) => p.anyAny).length,
      sinLog: items.filter((p) => !p.log).length,
      sinUtmAccept: accept.filter((p) => !p.utm).length,
      items,
    },
    snmpCommunities,
    fortiguard: null,
    collectedAt: new Date().toISOString(),
  };
}

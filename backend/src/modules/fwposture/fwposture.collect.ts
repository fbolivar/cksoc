/**
 * Recolección de postura del SonicWall (SOLO LECTURA) para el reporte de seguridad.
 * Lee estado + Security Rating nativo de SonicWall + configuración (cmdb) y arma un
 * "snapshot" SANITIZADO (sin secretos: contraseñas, llaves, psk) apto para evaluar
 * con checks deterministas y para el análisis con IA.
 */
import { fgGet } from '../response/fortigate.service';
import { logger } from '../../config/logger';

export interface FwAdmin { name: string; profile: string; twoFactor: string; trusthostOpen: boolean; sshKey: boolean; }
export interface FwPolicy { id: number; name: string; action: string; anyAny: boolean; log: boolean; utm: boolean; }
export interface FwIface { name: string; alias: string | null; role: string | null; allowaccess: string; wan: boolean; }

export interface FwSnapshot {
  device: { hostname: string; model: string; serial: string; version: string; build: string | number };
  securityRating: unknown | null;   // resultado nativo de SonicWall (para la IA)
  global: Record<string, unknown>;  // ajustes clave (sanitizados)
  admins: FwAdmin[];
  interfaces: FwIface[];
  policies: { total: number; enabled: number; anyAnyAccept: number; sinLog: number; sinUtmAccept: number; items: FwPolicy[] };
  snmpCommunities: number;          // comunidades SNMP v1/v2c configuradas
  fortiguard: Record<string, unknown> | null;
  collectedAt: string;
}

const TRUSTHOST_OPEN = /^0\.0\.0\.0[\s/]+0\.0\.0\.0$/;
function trusthostsOpen(a: Record<string, unknown>): boolean {
  // Todos los trusthost vacíos o 0.0.0.0/0 → sin restricción de origen.
  for (let i = 1; i <= 10; i++) {
    const v = String(a[`trusthost${i}`] ?? '').trim();
    if (v && !TRUSTHOST_OPEN.test(v)) return false; // hay al menos uno restringido
  }
  return true;
}

async function safe<T>(path: string, fallback: T): Promise<T> {
  try { return await fgGet<T>(path); } catch (err) { logger.warn({ err: err instanceof Error ? err.message : err, path }, 'fwposture: fallo al leer'); return fallback; }
}

export async function collectFwSnapshot(): Promise<FwSnapshot> {
  const [status, rating, global, adminsR, ifacesR, polR, snmpR, fg] = await Promise.all([
    safe<{ results?: Record<string, unknown> }>('/api/v2/monitor/system/status', {}),
    safe<{ results?: unknown }>('/api/v2/monitor/system/security-rating?scope=global', { results: null }),
    safe<{ results?: Record<string, unknown> }>('/api/v2/cmdb/system/global', {}),
    safe<{ results?: Record<string, unknown>[] }>('/api/v2/cmdb/system/admin', { results: [] }),
    safe<{ results?: Record<string, unknown>[] }>('/api/v2/cmdb/system/interface', { results: [] }),
    safe<{ results?: Record<string, unknown>[] }>('/api/v2/cmdb/firewall/policy', { results: [] }),
    safe<{ matched_count?: number; results?: unknown[] }>('/api/v2/cmdb/system.snmp/community', { results: [] }),
    safe<{ results?: Record<string, unknown> }>('/api/v2/monitor/system/fortiguard/server-info', { results: {} }),
  ]);

  const st = (status.results ?? {}) as Record<string, unknown>;
  const g = (global.results ?? {}) as Record<string, unknown>;

  const admins: FwAdmin[] = (adminsR.results ?? []).map((a) => ({
    name: String(a.name ?? ''),
    profile: String(a.accprofile ?? ''),
    twoFactor: String(a['two-factor'] ?? 'disable'),
    trusthostOpen: trusthostsOpen(a),
    sshKey: Boolean(String(a['ssh-public-key1'] ?? '').trim()),
  }));

  const interfaces: FwIface[] = (ifacesR.results ?? []).map((i) => ({
    name: String(i.name ?? ''),
    alias: (i.alias as string) || null,
    role: (i.role as string) || null,
    allowaccess: String(i.allowaccess ?? '').trim(),
    wan: /wan/i.test(String(i.name ?? '')) || String(i.role ?? '') === 'wan',
  }));

  const pols = (polR.results ?? []);
  const items: FwPolicy[] = pols.map((p) => {
    const src = (p.srcaddr as { name: string }[] ?? []).map((x) => x.name);
    const dst = (p.dstaddr as { name: string }[] ?? []).map((x) => x.name);
    const svc = (p.service as { name: string }[] ?? []).map((x) => x.name);
    const action = String(p.action ?? '');
    const anyAny = src.includes('all') && dst.includes('all') && svc.map((s) => s.toUpperCase()).includes('ALL');
    const log = ['all', 'utm'].includes(String(p.logtraffic ?? ''));
    const utm = String(p['utm-status'] ?? '') === 'enable';
    return { id: Number(p.policyid ?? 0), name: String(p.name ?? ''), action, anyAny, log, utm };
  });
  const accept = items.filter((p) => p.action === 'accept');

  // Ajustes globales sanitizados (solo postura, ningún secreto).
  const GLOBAL_KEYS = [
    'admintimeout', 'admin-lockout-threshold', 'admin-lockout-duration', 'admin-login-max',
    'strong-crypto', 'admin-https-redirect', 'admin-telnet', 'admin-ssh-v1', 'admin-scp',
    'admin-https-ssl-versions', 'gui-certificates', 'multi-factor-authentication', 'admin-console-timeout',
  ];
  const gClean: Record<string, unknown> = {};
  for (const k of GLOBAL_KEYS) if (g[k] !== undefined) gClean[k] = g[k];

  return {
    device: {
      hostname: String(st.hostname ?? 'SonicWall'),
      model: String(st.model_name ?? st.model ?? ''),
      serial: String(st.serial ?? ''),
      version: String(st.version ?? ''),
      build: (st.build as number) ?? '',
    },
    securityRating: rating.results ?? null,
    global: gClean,
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
    snmpCommunities: Number(snmpR.matched_count ?? (snmpR.results ?? []).length ?? 0),
    fortiguard: (fg.results as Record<string, unknown>) ?? null,
    collectedAt: new Date().toISOString(),
  };
}

/**
 * Checks deterministas de postura del FortiGate contra mejores prácticas de la
 * industria (alineados a CIS FortiGate / hardening de Fortinet). Salen de datos
 * reales de la config; la IA los redacta/prioriza, no los inventa.
 */
import type { FwSnapshot } from './fwposture.collect';

export type Sev = 'alta' | 'media' | 'baja';
export type Estado = 'fail' | 'warn' | 'pass' | 'na';

export interface Check {
  id: string;
  titulo: string;
  severidad: Sev;
  estado: Estado;
  evidencia: string;
  remediacion: string;
  referencia: string;
}

const MGMT = ['https', 'ssh', 'http', 'telnet'];

export function runChecks(s: FwSnapshot): Check[] {
  const c: Check[] = [];
  const g = s.global;
  const num = (k: string): number | null => (g[k] === undefined ? null : Number(g[k]));
  const str = (k: string): string | null => (g[k] === undefined ? null : String(g[k]));

  // 1) 2FA en administradores
  const sin2fa = s.admins.filter((a) => a.twoFactor === 'disable' && !a.sshKey);
  c.push({
    id: 'admin-2fa', titulo: 'Doble factor (2FA) en cuentas administrativas', severidad: 'alta',
    estado: s.admins.length === 0 ? 'na' : sin2fa.length ? 'fail' : 'pass',
    evidencia: sin2fa.length ? `${sin2fa.length} de ${s.admins.length} admin(s) sin 2FA: ${sin2fa.map((a) => a.name).join(', ')}` : 'Todas las cuentas admin usan 2FA o clave pública.',
    remediacion: 'Habilitar FortiToken/2FA en cada admin: config system admin → edit <user> → set two-factor fortitoken.',
    referencia: 'CIS FortiGate 1.x · Hardening de administración',
  });

  // 2) Restricción de origen (trusted hosts) del acceso admin
  const abiertos = s.admins.filter((a) => a.trusthostOpen);
  c.push({
    id: 'admin-trusthost', titulo: 'Restricción de origen del acceso administrativo (trusted hosts)', severidad: 'alta',
    estado: s.admins.length === 0 ? 'na' : abiertos.length ? 'fail' : 'pass',
    evidencia: abiertos.length ? `${abiertos.length} admin(s) accesibles desde cualquier IP: ${abiertos.map((a) => a.name).join(', ')}` : 'Todas las cuentas admin restringen el origen por trusted hosts.',
    remediacion: 'Limitar el acceso a las redes de gestión: config system admin → edit <user> → set trusthost1 <red> <máscara>.',
    referencia: 'CIS FortiGate · Restringir gestión a redes confiables',
  });

  // 3) Gestión expuesta en la interfaz WAN
  const wanExpuesta = s.interfaces.filter((i) => i.wan && MGMT.some((m) => i.allowaccess.split(/\s+/).includes(m)));
  c.push({
    id: 'wan-mgmt', titulo: 'Acceso de gestión expuesto a Internet (WAN)', severidad: 'alta',
    estado: wanExpuesta.length ? 'fail' : 'pass',
    evidencia: wanExpuesta.length ? `Interfaz(es) WAN con gestión: ${wanExpuesta.map((i) => `${i.name} [${i.allowaccess}]`).join('; ')}` : 'Ninguna interfaz WAN permite HTTPS/SSH/HTTP/Telnet de gestión.',
    remediacion: 'Quitar https/ssh/http/telnet del allowaccess de la WAN; gestionar por LAN o VPN.',
    referencia: 'CIS FortiGate · Sin gestión en interfaces no confiables',
  });

  // 4) Telnet de administración habilitado (protocolo inseguro)
  const telnet = str('admin-telnet');
  c.push({
    id: 'admin-telnet', titulo: 'Telnet de administración deshabilitado', severidad: 'media',
    estado: telnet === null ? 'na' : telnet === 'enable' ? 'fail' : 'pass',
    evidencia: telnet === 'enable' ? 'admin-telnet = enable (Telnet transmite en texto plano).' : 'Telnet de administración deshabilitado.',
    remediacion: 'config system global → set admin-telnet disable.',
    referencia: 'CIS FortiGate · Deshabilitar protocolos inseguros',
  });

  // 5) Tiempo de inactividad de sesión admin
  const to = num('admintimeout');
  c.push({
    id: 'admin-timeout', titulo: 'Tiempo de expiración de sesión administrativa', severidad: 'media',
    estado: to === null ? 'na' : to <= 30 ? 'pass' : to <= 60 ? 'warn' : 'fail',
    evidencia: to === null ? 'No disponible.' : `admintimeout = ${to} min (recomendado ≤ 30).`,
    remediacion: 'config system global → set admintimeout 15 (o ≤ 30).',
    referencia: 'CIS FortiGate · Expiración de sesiones inactivas',
  });

  // 6) Bloqueo por intentos fallidos
  const lock = num('admin-lockout-threshold');
  c.push({
    id: 'admin-lockout', titulo: 'Bloqueo de cuenta por intentos fallidos', severidad: 'baja',
    estado: lock === null ? 'na' : lock > 0 && lock <= 5 ? 'pass' : 'warn',
    evidencia: lock === null ? 'No disponible.' : `admin-lockout-threshold = ${lock}.`,
    remediacion: 'config system global → set admin-lockout-threshold 3.',
    referencia: 'CIS FortiGate · Protección contra fuerza bruta',
  });

  // 7) Criptografía fuerte
  const crypto = str('strong-crypto');
  c.push({
    id: 'strong-crypto', titulo: 'Criptografía fuerte habilitada', severidad: 'media',
    estado: crypto === null ? 'na' : crypto === 'enable' ? 'pass' : 'fail',
    evidencia: crypto === 'enable' ? 'strong-crypto = enable.' : `strong-crypto = ${crypto ?? '?'} (permite cifrados débiles).`,
    remediacion: 'config system global → set strong-crypto enable.',
    referencia: 'CIS FortiGate · Cifrado de servicios de gestión',
  });

  // 8) Políticas "any-any" que aceptan tráfico
  c.push({
    id: 'policy-anyany', titulo: 'Políticas permisivas (origen/destino/servicio = cualquiera)', severidad: 'media',
    estado: s.policies.anyAnyAccept === 0 ? 'pass' : 'warn',
    evidencia: s.policies.anyAnyAccept ? `${s.policies.anyAnyAccept} política(s) accept con src/dst/servicio = all.` : 'Sin políticas any-any de aceptación.',
    remediacion: 'Acotar origen, destino y servicio al mínimo necesario (principio de mínimo privilegio).',
    referencia: 'CIS FortiGate · Reglas de firewall específicas',
  });

  // 9) Políticas accept sin perfiles UTM (inspección)
  c.push({
    id: 'policy-utm', titulo: 'Inspección de seguridad (UTM) en políticas de salida', severidad: 'media',
    estado: s.policies.sinUtmAccept === 0 ? 'pass' : 'warn',
    evidencia: s.policies.sinUtmAccept ? `${s.policies.sinUtmAccept} de ${s.policies.items.filter((p) => p.action === 'accept').length} política(s) accept sin UTM (AV/IPS/web/app).` : 'Todas las políticas de aceptación aplican inspección UTM.',
    remediacion: 'Aplicar perfiles AV/IPS/Web/App e inspección SSL en las políticas que lo ameriten.',
    referencia: 'CIS FortiGate · Inspección de amenazas',
  });

  // 10) Registro (logging) en políticas
  c.push({
    id: 'policy-log', titulo: 'Registro de tráfico en políticas', severidad: 'baja',
    estado: s.policies.total === 0 ? 'na' : s.policies.sinLog === 0 ? 'pass' : 'warn',
    evidencia: s.policies.sinLog ? `${s.policies.sinLog} de ${s.policies.total} política(s) sin logging.` : 'Todas las políticas registran tráfico.',
    remediacion: 'set logtraffic all en las políticas relevantes (visibilidad y trazabilidad).',
    referencia: 'CIS FortiGate · Registro y monitoreo',
  });

  // 11) SNMP v1/v2c (comunidades)
  c.push({
    id: 'snmp-v2', titulo: 'SNMP v1/v2c (comunidades en texto plano)', severidad: 'media',
    estado: s.snmpCommunities > 0 ? 'fail' : 'pass',
    evidencia: s.snmpCommunities > 0 ? `${s.snmpCommunities} comunidad(es) SNMP v1/v2c configuradas.` : 'Sin comunidades SNMP v1/v2c.',
    remediacion: 'Usar SNMPv3 (autenticación + cifrado) y eliminar comunidades v1/v2c.',
    referencia: 'CIS FortiGate · SNMP seguro',
  });

  return c;
}

export function resumenChecks(checks: Check[]): { fail: number; warn: number; pass: number; na: number; score: number } {
  const fail = checks.filter((c) => c.estado === 'fail').length;
  const warn = checks.filter((c) => c.estado === 'warn').length;
  const pass = checks.filter((c) => c.estado === 'pass').length;
  const na = checks.filter((c) => c.estado === 'na').length;
  const evaluables = fail + warn + pass;
  // Puntaje simple: pass=1, warn=0.5, fail=0 sobre lo evaluable.
  const score = evaluables ? Math.round(((pass + warn * 0.5) / evaluables) * 100) : 0;
  return { fail, warn, pass, na, score };
}

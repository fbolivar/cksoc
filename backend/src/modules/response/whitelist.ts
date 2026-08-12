/**
 * Lista blanca y validaciones de bloqueo (capa de seguridad critica).
 * Se evalua SIEMPRE antes de cualquier accion de bloqueo en el FortiGate.
 *
 * Reglas (en orden):
 *  1. Debe ser una IPv4 valida.
 *  2. NUNCA bloquear IPs internas/privadas (RFC1918, loopback, link-local, CGNAT).
 *  3. NUNCA bloquear IPs de la lista blanca (gateway, DNS, IPs admin, IP de la entidad).
 *  4. NUNCA bloquear la IP desde la que el propio admin esta conectado.
 */
import { env } from '../../config/env';
import { isPublicIP } from '../geo/geoip.service';

export interface BlockCheck {
  allowed: boolean;
  reason?: string;
}

/** IPs criticas configuradas que jamas se bloquean. */
export function whitelistIps(): string[] {
  return env.RESPONSE_WHITELIST_IPS.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

function ipToInt(ip: string): number {
  const [a, b, c, d] = ip.split('.').map(Number);
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

/** Coincide una IP con una entrada de lista blanca: IP exacta o rango CIDR (a.b.c.d/n). */
function matchesEntry(ip: string, entry: string): boolean {
  if (entry.includes('/')) {
    const [net, bitsStr] = entry.split('/');
    const bits = Number(bitsStr);
    if (!isValidIpv4(net) || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipToInt(ip) & mask) === (ipToInt(net) & mask);
  }
  return ip === entry;
}

/** True si la IP esta en la lista blanca (IP exacta o dentro de un CIDR). */
export function isWhitelisted(ip: string): boolean {
  return whitelistIps().some((e) => matchesEntry(ip, e));
}

/**
 * Determina si una IP puede bloquearse de forma segura.
 * @param ip       IP candidata
 * @param adminIp  IP de origen del admin que solicita (no se puede auto-bloquear)
 */
export function canBlock(ip: string, adminIp?: string): BlockCheck {
  if (!ip || !isValidIpv4(ip)) {
    return { allowed: false, reason: 'La IP no es una IPv4 valida' };
  }
  // 2. Interna/privada
  if (!isPublicIP(ip)) {
    return { allowed: false, reason: 'Es una IP interna/privada: bloqueo prohibido' };
  }
  // 3. Lista blanca de IPs criticas (IP exacta o rango CIDR)
  if (isWhitelisted(ip)) {
    return { allowed: false, reason: 'La IP esta en la lista blanca (infraestructura critica de HexWatch)' };
  }
  // 4. IP del propio admin
  if (adminIp && normalizeIp(adminIp) === ip) {
    return { allowed: false, reason: 'No puedes bloquear tu propia IP de conexion' };
  }
  return { allowed: true };
}

/** Normaliza una IP de Express (puede venir como ::ffff:1.2.3.4). */
export function normalizeIp(ip: string): string {
  return ip.replace(/^::ffff:/, '');
}

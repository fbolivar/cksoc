/**
 * Servicio de geolocalizacion de IPs (MaxMind GeoLite2-City local).
 * La base se carga una sola vez al iniciar. Solo se geolocalizan IPs publicas.
 */
import maxmind, { type CityResponse, type Reader } from 'maxmind';
import { existsSync } from 'node:fs';
import { env } from '../../config/env';

export interface GeoLocation {
  ip: string;
  country: string;
  city: string;
  lat: number;
  lon: number;
  isoCode: string;
}

let reader: Reader<CityResponse> | null = null;
let loadError: string | null = null;

/** Carga la base GeoLite2 al iniciar el backend. */
export async function initGeoIp(): Promise<void> {
  try {
    if (!existsSync(env.GEOIP_DB_PATH)) {
      loadError = `No se encontro la base GeoLite2 en ${env.GEOIP_DB_PATH}`;
      // eslint-disable-next-line no-console
      console.warn('⚠️  ' + loadError);
      return;
    }
    reader = await maxmind.open<CityResponse>(env.GEOIP_DB_PATH);
    // eslint-disable-next-line no-console
    console.log('🌎 GeoLite2 cargada:', env.GEOIP_DB_PATH);
  } catch (err) {
    loadError = err instanceof Error ? err.message : 'error cargando GeoLite2';
    console.error('⚠️  No se pudo cargar GeoLite2:', loadError);
  }
}

export function isGeoReady(): boolean {
  return reader !== null;
}
export function geoError(): string | null {
  return loadError;
}

/**
 * Determina si una IP es publica (descarta RFC1918, loopback, link-local, CGNAT).
 */
export function isPublicIP(ip: string): boolean {
  if (!ip) return false;
  // IPv6 basico: descarta loopback (::1), ULA (fc00::/7) y link-local (fe80::/10)
  if (ip.includes(':')) {
    const low = ip.toLowerCase();
    if (low === '::1' || low.startsWith('fe8') || low.startsWith('fe9') || low.startsWith('fea') || low.startsWith('feb')) return false;
    if (low.startsWith('fc') || low.startsWith('fd')) return false;
    return true;
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return false; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return false; // 172.16.0.0/12
  if (a === 192 && b === 168) return false; // 192.168.0.0/16
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64.0.0/10
  if (a === 0) return false;
  if (a >= 224) return false; // multicast/reservado
  return true;
}

/**
 * Geolocaliza una IP publica. Devuelve null si es privada o no se encuentra.
 */
export function geolocate(ip: string): GeoLocation | null {
  if (!reader || !isPublicIP(ip)) return null;
  const res = reader.get(ip);
  if (!res || !res.location || res.location.latitude == null || res.location.longitude == null) {
    return null;
  }
  return {
    ip,
    country: res.country?.names?.es || res.country?.names?.en || 'Desconocido',
    city: res.city?.names?.es || res.city?.names?.en || '',
    lat: res.location.latitude,
    lon: res.location.longitude,
    isoCode: res.country?.iso_code || '',
  };
}

/** Dada una alerta, escoge la primera IP publica entre srcip y remip. */
export function extractPublicIp(data: { srcip?: string; remip?: string }): string | null {
  for (const ip of [data.srcip, data.remip]) {
    if (ip && isPublicIP(ip)) return ip;
  }
  return null;
}

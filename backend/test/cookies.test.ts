/**
 * Parseo de cookies: el token de sesion viaja en una cookie HttpOnly y se lee
 * del header Cookie sin dependencias externas. Casos borde del parser.
 */
import { describe, it, expect } from 'vitest';
import { getCookie } from '../src/config/cookies';

describe('getCookie', () => {
  it('devuelve null si no hay header', () => {
    expect(getCookie(undefined, 'token')).toBeNull();
  });

  it('extrae la cookie por nombre entre varias', () => {
    const header = 'theme=dark; token=abc.def.ghi; lang=es';
    expect(getCookie(header, 'token')).toBe('abc.def.ghi');
    expect(getCookie(header, 'theme')).toBe('dark');
    expect(getCookie(header, 'lang')).toBe('es');
  });

  it('devuelve null si la cookie no existe', () => {
    expect(getCookie('otra=1; mas=2', 'token')).toBeNull();
  });

  it('decodifica valores URL-encoded', () => {
    expect(getCookie('token=a%20b%3Dc', 'token')).toBe('a b=c');
  });

  it('no confunde nombres que son prefijo de otros', () => {
    expect(getCookie('access_token=zzz; token=yyy', 'token')).toBe('yyy');
  });
});

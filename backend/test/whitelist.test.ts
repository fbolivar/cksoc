/**
 * Lista blanca de bloqueo: es la barrera critica antes de cualquier accion en
 * el FortiGate. Se valida el saneamiento de IPv4 y las reglas de "no bloquear".
 */
import { describe, it, expect } from 'vitest';
import { isValidIpv4, normalizeIp, canBlock } from '../src/modules/response/whitelist';

describe('isValidIpv4', () => {
  it('acepta IPv4 validas', () => {
    expect(isValidIpv4('8.8.8.8')).toBe(true);
    expect(isValidIpv4('192.168.1.1')).toBe(true);
    expect(isValidIpv4('0.0.0.0')).toBe(true);
    expect(isValidIpv4('255.255.255.255')).toBe(true);
  });

  it('rechaza octetos fuera de rango', () => {
    expect(isValidIpv4('999.999.999.999')).toBe(false);
    expect(isValidIpv4('256.0.0.1')).toBe(false);
  });

  it('rechaza ceros a la izquierda (evita interpretaciones ambiguas/octales)', () => {
    expect(isValidIpv4('01.2.3.4')).toBe(false);
    expect(isValidIpv4('1.2.3.04')).toBe(false);
  });

  it('rechaza formatos no IPv4', () => {
    expect(isValidIpv4('1.2.3')).toBe(false);
    expect(isValidIpv4('1.2.3.4.5')).toBe(false);
    expect(isValidIpv4('a.b.c.d')).toBe(false);
    expect(isValidIpv4('')).toBe(false);
    expect(isValidIpv4('1.2.3.-4')).toBe(false);
  });
});

describe('normalizeIp', () => {
  it('quita el prefijo IPv4-mapped ::ffff:', () => {
    expect(normalizeIp('::ffff:1.2.3.4')).toBe('1.2.3.4');
  });
  it('deja intacta una IPv4 normal', () => {
    expect(normalizeIp('9.9.9.9')).toBe('9.9.9.9');
  });
});

describe('canBlock', () => {
  it('rechaza una IP invalida', () => {
    expect(canBlock('no-es-ip').allowed).toBe(false);
  });

  it('rechaza IPs internas/privadas', () => {
    expect(canBlock('10.0.0.5').allowed).toBe(false);
    expect(canBlock('192.168.1.10').allowed).toBe(false);
    expect(canBlock('127.0.0.1').allowed).toBe(false);
  });

  it('rechaza bloquear la propia IP del admin', () => {
    expect(canBlock('8.8.8.8', '8.8.8.8').allowed).toBe(false);
  });

  it('permite bloquear una IP publica ajena (lista blanca vacia por defecto)', () => {
    expect(canBlock('8.8.8.8').allowed).toBe(true);
  });
});

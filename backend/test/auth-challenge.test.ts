/** Reto de 2FA: el token de corta duracion que liga el paso 1 y el paso 2 del login. */
import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import { signChallenge, verifyChallenge } from '../src/modules/auth/auth.service';
import { env } from '../src/config/env';

describe('reto 2FA (challenge)', () => {
  it('firma y verifica el reto devolviendo el userId', () => {
    const challenge = signChallenge('user-abc-123');
    expect(verifyChallenge(challenge)).toBe('user-abc-123');
  });

  it('rechaza un token de sesion normal (proposito incorrecto)', () => {
    const sessionToken = jwt.sign({ sub: 'u', email: 'a@b.co', role: 'admin' }, env.JWT_SECRET);
    expect(() => verifyChallenge(sessionToken)).toThrow();
  });

  it('rechaza un token firmado con otra clave', () => {
    const foreign = jwt.sign({ sub: 'u', purpose: '2fa' }, 'otra-clave-distinta-xyz');
    expect(() => verifyChallenge(foreign)).toThrow();
  });

  it('rechaza basura que no es un JWT', () => {
    expect(() => verifyChallenge('esto-no-es-un-jwt')).toThrow();
  });
});

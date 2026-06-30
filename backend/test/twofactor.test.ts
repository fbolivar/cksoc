/** Cifrado del secreto TOTP: AES-256-GCM autenticado (confidencialidad + integridad). */
import { describe, it, expect } from 'vitest';
import { encryptSecret, decryptSecret } from '../src/modules/auth/twofactor.service';

describe('cifrado del secreto TOTP', () => {
  it('descifra exactamente lo que cifro (round-trip)', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    expect(decryptSecret(encryptSecret(secret))).toBe(secret);
  });

  it('usa un IV aleatorio: dos cifrados del mismo valor difieren', () => {
    expect(encryptSecret('mismo-valor')).not.toBe(encryptSecret('mismo-valor'));
  });

  it('detecta manipulacion del texto cifrado (tag GCM)', () => {
    const blob = encryptSecret('secreto-sensible');
    const parts = blob.split(':');
    parts[2] = Buffer.from('payload-manipulado').toString('base64');
    expect(() => decryptSecret(parts.join(':'))).toThrow();
  });
});

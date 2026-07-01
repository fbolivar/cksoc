/** Integracion (BD real): ciclo de 2FA (setup/enable/verify/backup/disable). */
import { describe, it, expect, beforeAll } from 'vitest';
import { authenticator } from 'otplib';
import { registerUser } from '../../src/modules/auth/auth.service';
import { setup, enable, verifyCode, disable, getStatus } from '../../src/modules/auth/twofactor.service';

const password = 'password123';
let userId: string;

describe('2FA (integracion con BD)', () => {
  beforeAll(async () => {
    const u = await registerUser(`2fa-${Date.now()}@test.local`, password, 'Usuario 2FA', 'lector');
    userId = u.id;
  });

  it('setup -> enable -> verificar TOTP y codigo de respaldo -> disable', async () => {
    const { secret } = await setup(userId, '2fa@test.local');
    expect((await getStatus(userId)).enabled).toBe(false);

    const { backupCodes } = await enable(userId, authenticator.generate(secret));
    expect(backupCodes).toHaveLength(10);
    expect((await getStatus(userId)).enabled).toBe(true);

    // TOTP valido / invalido
    expect(await verifyCode(userId, authenticator.generate(secret))).toBe(true);
    expect(await verifyCode(userId, '000000')).toBe(false);

    // Codigo de respaldo: valido una vez, luego consumido
    expect(await verifyCode(userId, backupCodes[0])).toBe(true);
    expect(await verifyCode(userId, backupCodes[0])).toBe(false);

    await disable(userId, password, authenticator.generate(secret));
    expect((await getStatus(userId)).enabled).toBe(false);
  });
});

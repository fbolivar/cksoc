/** Integracion (BD real): login, credenciales y revocacion de sesiones. */
import { describe, it, expect, beforeAll } from 'vitest';
import type { Request, Response } from 'express';
import { registerUser, loginUser, revokeSessions } from '../../src/modules/auth/auth.service';
import { authenticate } from '../../src/middleware/auth';

const email = `auth-${Date.now()}@test.local`;
let userId: string;

/** Ejecuta authenticate con un token y reporta si llamo next() y el codigo HTTP. */
async function runAuth(token?: string): Promise<{ passed: boolean; code?: number }> {
  const req = { headers: token ? { authorization: `Bearer ${token}` } : {} } as unknown as Request;
  let code: number | undefined;
  const res = {
    status(c: number) { code = c; return this; },
    json() { return this; },
  } as unknown as Response;
  let passed = false;
  await authenticate(req, res, () => { passed = true; });
  return { passed, code };
}

describe('auth (integracion con BD)', () => {
  beforeAll(async () => {
    const u = await registerUser(email, 'password123', 'Usuario Auth', 'analista');
    userId = u.id;
  });

  it('login correcto emite un token', async () => {
    const res = await loginUser(email, 'password123');
    expect('token' in res && res.token).toBeTruthy();
  });

  it('login con contrasena incorrecta lanza 401', async () => {
    await expect(loginUser(email, 'malaclave')).rejects.toMatchObject({ status: 401 });
  });

  it('token valido pasa authenticate y tras revocar deja de valer', async () => {
    const res = await loginUser(email, 'password123');
    const token = 'token' in res ? res.token : '';

    const before = await runAuth(token);
    expect(before.passed).toBe(true);

    await revokeSessions(userId); // incrementa token_version

    const after = await runAuth(token);
    expect(after.passed).toBe(false);
    expect(after.code).toBe(401);
  });
});

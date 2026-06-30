/** RBAC: el middleware requireRole es la barrera de autorizacion del SOC. */
import { describe, it, expect, vi } from 'vitest';
import type { Request, Response } from 'express';
import { requireRole } from '../src/middleware/roles';

function mockRes() {
  const res = {} as Response & { status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> };
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

describe('requireRole', () => {
  it('deja pasar al rol permitido', () => {
    const req = { user: { role: 'admin' } } as unknown as Request;
    const res = mockRes();
    const next = vi.fn();
    requireRole('admin', 'analista')(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  it('bloquea con 403 a un rol no autorizado', () => {
    const req = { user: { role: 'lector' } } as unknown as Request;
    const res = mockRes();
    const next = vi.fn();
    requireRole('admin')(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('bloquea con 401 si no hay usuario autenticado', () => {
    const req = {} as Request;
    const res = mockRes();
    const next = vi.fn();
    requireRole('admin')(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

/** Controladores de gestion de usuarios. */
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  listUsers,
  adminCreateUser,
  adminUpdateUser,
  adminResetPassword,
  adminDeleteUser,
  changeOwnPassword,
  getUser,
  countActiveAdmins,
} from './users.service';
import { HttpError } from '../auth/auth.service';

const role = z.enum(['admin', 'analista', 'lector']);

const createSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  fullName: z.string().min(2),
  role,
});

const updateSchema = z.object({
  fullName: z.string().min(2).optional(),
  role: role.optional(),
  isActive: z.boolean().optional(),
});

export async function getUsers(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ users: await listUsers() });
  } catch (err) {
    handle(err, res);
  }
}

export async function postUser(req: Request, res: Response): Promise<void> {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const { email, password, fullName, role: r } = parsed.data;
    res.status(201).json({ user: await adminCreateUser(email, password, fullName, r) });
  } catch (err) {
    handle(err, res);
  }
}

export async function putUser(req: Request, res: Response): Promise<void> {
  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos' });
    return;
  }
  try {
    // Salvaguarda: no permitir que el admin se quite a si mismo el rol o se desactive
    // si es el ultimo admin activo.
    const target = await getUser(req.params.id);
    const demoting = parsed.data.role && parsed.data.role !== 'admin' && target.role === 'admin';
    const deactivating = parsed.data.isActive === false && target.role === 'admin';
    if ((demoting || deactivating) && (await countActiveAdmins()) <= 1) {
      throw new HttpError(400, 'No puedes dejar el sistema sin administradores activos');
    }
    res.json({ user: await adminUpdateUser(req.params.id, parsed.data) });
  } catch (err) {
    handle(err, res);
  }
}

export async function resetPassword(req: Request, res: Response): Promise<void> {
  const parsed = z.object({ password: z.string().min(8) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'La contrasena debe tener al menos 8 caracteres' });
    return;
  }
  try {
    await adminResetPassword(req.params.id, parsed.data.password);
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

export async function deleteUser(req: Request, res: Response): Promise<void> {
  try {
    if (req.params.id === req.user!.id) {
      throw new HttpError(400, 'No puedes eliminar tu propio usuario');
    }
    const target = await getUser(req.params.id);
    if (target.role === 'admin' && (await countActiveAdmins()) <= 1) {
      throw new HttpError(400, 'No puedes eliminar al ultimo administrador');
    }
    await adminDeleteUser(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

export async function changePassword(req: Request, res: Response): Promise<void> {
  const parsed = z
    .object({ currentPassword: z.string().min(1), newPassword: z.string().min(8) })
    .safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'La nueva contrasena debe tener al menos 8 caracteres' });
    return;
  }
  try {
    await changeOwnPassword(req.user!.id, parsed.data.currentPassword, parsed.data.newPassword);
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Error en usuarios:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
}

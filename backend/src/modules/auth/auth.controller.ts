/**
 * Controladores HTTP del modulo de autenticacion.
 * Valida entradas con zod y delega en el service.
 */
import type { Request, Response } from 'express';
import { z } from 'zod';
import { registerUser, loginUser, getProfile, HttpError } from './auth.service';

const credentialsSchema = z.object({
  email: z.string().email('Correo invalido'),
  password: z.string().min(8, 'La contrasena debe tener al menos 8 caracteres'),
});

const registerSchema = credentialsSchema.extend({
  fullName: z.string().min(2, 'Nombre invalido'),
  role: z.enum(['admin', 'analista', 'lector']).optional(),
});

export async function register(req: Request, res: Response): Promise<void> {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const { email, password, fullName, role } = parsed.data;
    const user = await registerUser(email, password, fullName, role);
    res.status(201).json({ user });
  } catch (err) {
    handleError(err, res);
  }
}

export async function login(req: Request, res: Response): Promise<void> {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const { email, password } = parsed.data;
    const result = await loginUser(email, password);
    res.json(result);
  } catch (err) {
    handleError(err, res);
  }
}

export async function me(req: Request, res: Response): Promise<void> {
  try {
    const user = await getProfile(req.user!.id);
    res.json({ user });
  } catch (err) {
    handleError(err, res);
  }
}

function handleError(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Error en auth:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
}

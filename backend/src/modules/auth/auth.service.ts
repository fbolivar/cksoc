/**
 * Logica de autenticacion: registro, login, hash de contrasenas y emision de JWT.
 */
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { query } from '../../config/db';
import { env } from '../../config/env';
import type { AuthUser, JwtPayload, RoleName } from '../../types';

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  full_name: string;
  is_active: boolean;
  role: RoleName;
}

const SALT_ROUNDS = 12;

/** Registra un usuario nuevo. Por defecto se le asigna el rol indicado (default: lector). */
export async function registerUser(
  email: string,
  password: string,
  fullName: string,
  role: RoleName = 'lector'
): Promise<AuthUser> {
  const existing = await query<{ id: string }>(
    'SELECT id FROM users WHERE email = $1',
    [email]
  );
  if (existing.length > 0) {
    throw new HttpError(409, 'Ya existe un usuario con ese correo');
  }

  const roleRows = await query<{ id: number }>(
    'SELECT id FROM roles WHERE name = $1',
    [role]
  );
  if (roleRows.length === 0) {
    throw new HttpError(400, `Rol invalido: ${role}`);
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const rows = await query<UserRow>(
    `INSERT INTO users (email, password_hash, full_name, role_id)
     VALUES ($1, $2, $3, $4)
     RETURNING id, email, password_hash, full_name, is_active,
       (SELECT name FROM roles WHERE id = $4) AS role`,
    [email, passwordHash, fullName, roleRows[0].id]
  );

  return toAuthUser(rows[0]);
}

/** Verifica credenciales y devuelve el usuario + token. */
export async function loginUser(
  email: string,
  password: string
): Promise<{ user: AuthUser; token: string }> {
  const rows = await query<UserRow>(
    `SELECT u.id, u.email, u.password_hash, u.full_name, u.is_active, r.name AS role
       FROM users u
       JOIN roles r ON r.id = u.role_id
      WHERE u.email = $1`,
    [email]
  );

  const user = rows[0];
  if (!user) {
    throw new HttpError(401, 'Credenciales invalidas');
  }
  if (!user.is_active) {
    throw new HttpError(403, 'Usuario desactivado');
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    throw new HttpError(401, 'Credenciales invalidas');
  }

  await query('UPDATE users SET last_login_at = now() WHERE id = $1', [user.id]);

  const authUser = toAuthUser(user);
  const token = signToken(authUser);
  return { user: authUser, token };
}

/** Devuelve el perfil del usuario autenticado. */
export async function getProfile(userId: string): Promise<AuthUser> {
  const rows = await query<UserRow>(
    `SELECT u.id, u.email, u.password_hash, u.full_name, u.is_active, r.name AS role
       FROM users u JOIN roles r ON r.id = u.role_id
      WHERE u.id = $1`,
    [userId]
  );
  if (rows.length === 0) {
    throw new HttpError(404, 'Usuario no encontrado');
  }
  return toAuthUser(rows[0]);
}

function signToken(user: AuthUser): string {
  const payload: JwtPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
  };
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN as jwt.SignOptions['expiresIn'],
  });
}

function toAuthUser(row: UserRow): AuthUser {
  return {
    id: row.id,
    email: row.email,
    fullName: row.full_name,
    role: row.role,
  };
}

/** Error con codigo HTTP para manejarlo en el controller. */
export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

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
  totp_enabled?: boolean;
  token_version?: number;
}

/** Resultado del login: sesion completa, o reto de 2FA pendiente. */
export type LoginResult =
  | { user: AuthUser; token: string }
  | { twoFactor: true; challenge: string };

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
): Promise<LoginResult> {
  const rows = await query<UserRow>(
    `SELECT u.id, u.email, u.password_hash, u.full_name, u.is_active, u.totp_enabled, u.token_version, r.name AS role
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

  // Si el usuario tiene 2FA activo, no se emite la sesion: se entrega un reto
  // de corta duracion que se canjea con el codigo TOTP en /auth/login/2fa.
  if (user.totp_enabled) {
    return { twoFactor: true, challenge: signChallenge(user.id) };
  }

  await query('UPDATE users SET last_login_at = now() WHERE id = $1', [user.id]);

  const authUser = toAuthUser(user);
  const token = signToken(authUser, user.token_version ?? 0);
  return { user: authUser, token };
}

/** Firma un reto de 2FA de corta duracion (5 min) ligado al usuario. */
export function signChallenge(userId: string): string {
  return jwt.sign({ sub: userId, purpose: '2fa' }, env.JWT_SECRET, { expiresIn: '5m' });
}

/** Valida un reto de 2FA y devuelve el id del usuario. */
export function verifyChallenge(token: string): string {
  try {
    const p = jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }) as { sub: string; purpose?: string };
    if (p.purpose !== '2fa') throw new Error('proposito invalido');
    return p.sub;
  } catch {
    throw new HttpError(401, 'Reto 2FA invalido o expirado');
  }
}

/** Emite la sesion (user + token) de un usuario ya autenticado por 2FA. */
export async function issueSessionForUser(userId: string): Promise<{ user: AuthUser; token: string }> {
  const authUser = await getProfile(userId);
  const tv = await getTokenVersion(userId);
  await query('UPDATE users SET last_login_at = now() WHERE id = $1', [userId]);
  return { user: authUser, token: signToken(authUser, tv) };
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

function signToken(user: AuthUser, tokenVersion: number): string {
  const payload: JwtPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    tv: tokenVersion,
  };
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN as jwt.SignOptions['expiresIn'],
  });
}

/** Lee la version de token actual del usuario (0 si no se encuentra). */
async function getTokenVersion(userId: string): Promise<number> {
  const rows = await query<{ token_version: number }>(
    'SELECT token_version FROM users WHERE id = $1',
    [userId]
  );
  return rows[0]?.token_version ?? 0;
}

/**
 * Revoca todas las sesiones del usuario (incrementa token_version) y emite una
 * sesion nueva para el dispositivo actual. Los demas tokens quedan invalidos.
 */
export async function revokeSessions(userId: string): Promise<{ user: AuthUser; token: string }> {
  const rows = await query<{ token_version: number }>(
    'UPDATE users SET token_version = token_version + 1 WHERE id = $1 RETURNING token_version',
    [userId]
  );
  if (rows.length === 0) throw new HttpError(404, 'Usuario no encontrado');
  const authUser = await getProfile(userId);
  return { user: authUser, token: signToken(authUser, rows[0].token_version) };
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

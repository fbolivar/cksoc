/**
 * Gestion de usuarios (Fase 5). Operaciones de administracion + cambio de
 * contrasena propia. El hashing usa bcrypt (mismo coste que el registro).
 */
import bcrypt from 'bcryptjs';
import { query } from '../../config/db';
import { HttpError } from '../auth/auth.service';
import type { RoleName } from '../../types';

const SALT_ROUNDS = 12;

export interface UserListItem {
  id: string;
  email: string;
  fullName: string;
  role: RoleName;
  isActive: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}

interface Row {
  id: string;
  email: string;
  full_name: string;
  role: RoleName;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

const toItem = (r: Row): UserListItem => ({
  id: r.id,
  email: r.email,
  fullName: r.full_name,
  role: r.role,
  isActive: r.is_active,
  lastLoginAt: r.last_login_at,
  createdAt: r.created_at,
});

const SELECT = `
  SELECT u.id, u.email, u.full_name, u.is_active, u.last_login_at, u.created_at, r.name AS role
    FROM users u JOIN roles r ON r.id = u.role_id`;

async function roleId(role: RoleName): Promise<number> {
  const rows = await query<{ id: number }>('SELECT id FROM roles WHERE name = $1', [role]);
  if (rows.length === 0) throw new HttpError(400, `Rol invalido: ${role}`);
  return rows[0].id;
}

export async function listUsers(): Promise<UserListItem[]> {
  const rows = await query<Row>(`${SELECT} ORDER BY u.created_at ASC`);
  return rows.map(toItem);
}

export async function adminCreateUser(
  email: string,
  password: string,
  fullName: string,
  role: RoleName
): Promise<UserListItem> {
  const exists = await query<{ id: string }>('SELECT id FROM users WHERE email = $1', [email]);
  if (exists.length > 0) throw new HttpError(409, 'Ya existe un usuario con ese correo');
  const rid = await roleId(role);
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const rows = await query<Row>(
    `WITH ins AS (
       INSERT INTO users (email, password_hash, full_name, role_id)
       VALUES ($1,$2,$3,$4) RETURNING id, email, full_name, is_active, last_login_at, created_at, role_id
     )
     SELECT ins.id, ins.email, ins.full_name, ins.is_active, ins.last_login_at, ins.created_at,
            (SELECT name FROM roles WHERE id = ins.role_id) AS role
       FROM ins`,
    [email, hash, fullName, rid]
  );
  return toItem(rows[0]);
}

export async function adminUpdateUser(
  id: string,
  data: { fullName?: string; role?: RoleName; isActive?: boolean }
): Promise<UserListItem> {
  const rid = data.role ? await roleId(data.role) : null;
  const rows = await query<Row>(
    `UPDATE users SET
       full_name = COALESCE($2, full_name),
       role_id   = COALESCE($3, role_id),
       is_active = COALESCE($4, is_active),
       updated_at = now()
     WHERE id = $1
     RETURNING id`,
    [id, data.fullName ?? null, rid, data.isActive ?? null]
  );
  if (rows.length === 0) throw new HttpError(404, 'Usuario no encontrado');
  return getUser(id);
}

export async function adminResetPassword(id: string, newPassword: string): Promise<void> {
  const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  // Incrementa token_version para invalidar las sesiones activas del usuario.
  const rows = await query<{ id: string }>(
    'UPDATE users SET password_hash = $2, token_version = token_version + 1, updated_at = now() WHERE id = $1 RETURNING id',
    [id, hash]
  );
  if (rows.length === 0) throw new HttpError(404, 'Usuario no encontrado');
}

export async function adminDeleteUser(id: string): Promise<void> {
  const rows = await query<{ id: string }>('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
  if (rows.length === 0) throw new HttpError(404, 'Usuario no encontrado');
}

export async function getUser(id: string): Promise<UserListItem> {
  const rows = await query<Row>(`${SELECT} WHERE u.id = $1`, [id]);
  if (rows.length === 0) throw new HttpError(404, 'Usuario no encontrado');
  return toItem(rows[0]);
}

/** Cambio de contrasena del propio usuario autenticado. */
export async function changeOwnPassword(
  userId: string,
  current: string,
  next: string
): Promise<void> {
  const rows = await query<{ password_hash: string }>(
    'SELECT password_hash FROM users WHERE id = $1',
    [userId]
  );
  if (rows.length === 0) throw new HttpError(404, 'Usuario no encontrado');
  const ok = await bcrypt.compare(current, rows[0].password_hash);
  if (!ok) throw new HttpError(401, 'La contrasena actual es incorrecta');
  const hash = await bcrypt.hash(next, SALT_ROUNDS);
  // Incrementa token_version: invalida las demas sesiones tras el cambio.
  await query(
    'UPDATE users SET password_hash = $2, token_version = token_version + 1, updated_at = now() WHERE id = $1',
    [userId, hash]
  );
}

/** Cuenta admins activos (para evitar quedarse sin administradores). */
export async function countActiveAdmins(): Promise<number> {
  const rows = await query<{ n: string }>(
    `SELECT COUNT(*)::int AS n FROM users u JOIN roles r ON r.id = u.role_id
      WHERE r.name = 'admin' AND u.is_active = TRUE`
  );
  return Number(rows[0].n);
}

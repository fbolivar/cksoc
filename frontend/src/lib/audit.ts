/** Cliente del registro de auditoria (solo admin). */
import { api } from './api';

export interface AuditItem {
  id: string;
  createdAt: string;
  actorEmail: string | null;
  action: string;
  target: string | null;
  result: 'ok' | 'fail';
  ip: string | null;
  detail: unknown;
}

export interface AuditQuery {
  action?: string;
  actor?: string;
  result?: string;
  from?: string;
  to?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export const auditApi = {
  list: (params: AuditQuery) =>
    api.get<{ items: AuditItem[]; total: number }>('/audit', { params }).then((r) => r.data),
  actions: () => api.get<{ actions: string[] }>('/audit/actions').then((r) => r.data.actions),
};

/** Etiqueta legible por accion. */
export const ACTION_LABELS: Record<string, string> = {
  login: 'Inicio de sesión',
  login_failed: 'Inicio de sesión fallido',
  login_2fa: 'Verificación 2FA',
  login_2fa_failed: 'Verificación 2FA fallida',
  logout_all: 'Cierre de todas las sesiones',
  user_create: 'Usuario creado',
  user_update: 'Usuario modificado',
  user_delete: 'Usuario eliminado',
  user_password_reset: 'Contraseña restablecida (admin)',
  password_change: 'Cambio de contraseña propia',
  backup_create: 'Respaldo creado',
  backup_delete: 'Respaldo eliminado',
};

export const actionLabel = (a: string): string => ACTION_LABELS[a] ?? a;

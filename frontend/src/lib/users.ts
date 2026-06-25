/** Tipos y llamadas a la API de gestion de usuarios. */
import { api } from './api';

export type RoleName = 'admin' | 'analista' | 'lector';

export interface User {
  id: string;
  email: string;
  fullName: string;
  role: RoleName;
  isActive: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}

export interface UserInput {
  email: string;
  password: string;
  fullName: string;
  role: RoleName;
}

export const usersApi = {
  list: () => api.get<{ users: User[] }>('/users').then((r) => r.data.users),
  create: (input: UserInput) => api.post<{ user: User }>('/users', input).then((r) => r.data.user),
  update: (id: string, data: { fullName?: string; role?: RoleName; isActive?: boolean }) =>
    api.put<{ user: User }>(`/users/${id}`, data).then((r) => r.data.user),
  resetPassword: (id: string, password: string) =>
    api.post(`/users/${id}/reset-password`, { password }).then((r) => r.data),
  remove: (id: string) => api.delete(`/users/${id}`).then((r) => r.data),
  changeOwnPassword: (currentPassword: string, newPassword: string) =>
    api.post('/users/me/change-password', { currentPassword, newPassword }).then((r) => r.data),
};

export const ROLE_LABELS: Record<RoleName, string> = {
  admin: 'Administrador',
  analista: 'Analista',
  lector: 'Lector',
};

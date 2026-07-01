/** API de la cuenta propia: 2FA (TOTP) y cambio de contrasena. */
import { api } from './api';

export const twofaApi = {
  status: () => api.get<{ enabled: boolean }>('/auth/2fa/status').then((r) => r.data),
  setup: () => api.post<{ otpauth: string; qr: string; secret: string }>('/auth/2fa/setup').then((r) => r.data),
  enable: (code: string) => api.post<{ backupCodes: string[] }>('/auth/2fa/enable', { code }).then((r) => r.data),
  disable: (password: string, code: string) =>
    api.post<{ enabled: boolean }>('/auth/2fa/disable', { password, code }).then((r) => r.data),
};

export const sessionApi = {
  /** Cierra todas las sesiones (revoca tokens) y devuelve un token fresco para esta. */
  logoutAll: () => api.post<{ token: string }>('/auth/logout-all').then((r) => r.data),
};

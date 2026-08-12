/**
 * Contexto de autenticacion del frontend.
 * Mantiene el usuario actual, gestiona login/logout y restaura sesion al cargar.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { AxiosError } from 'axios';
import { api, tokenStorage } from './api';

export type RoleName = 'admin' | 'analista' | 'lector';

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: RoleName;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<LoginStep>;
  loginVerify2fa: (challenge: string, code: string) => Promise<void>;
  logout: () => void;
}

/** Respuesta del paso 1 del login: sesion lista, o reto de 2FA pendiente. */
export type LoginStep =
  | { twoFactor: false }
  | { twoFactor: true; challenge: string };

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Al montar: intenta recuperar el perfil. La sesion vive en la cookie HttpOnly
  // (o, en sesiones antiguas, en el token de localStorage que el interceptor
  // adjunta). Un 401 significa que no hay sesion valida.
  useEffect(() => {
    api
      .get<{ user: AuthUser }>('/auth/me')
      .then((res) => setUser(res.data.user))
      .catch((err) => {
        // Solo limpiar el token legado si es invalido/expirado (401). Un 500,
        // timeout o corte de red momentaneo NO debe desloguear a un usuario
        // con sesion valida.
        if ((err as AxiosError).response?.status === 401) tokenStorage.clear();
      })
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string): Promise<LoginStep> {
    const res = await api.post<
      { user: AuthUser; token: string } | { twoFactor: true; challenge: string }
    >('/auth/login', { email, password });
    if ('twoFactor' in res.data && res.data.twoFactor) {
      return { twoFactor: true, challenge: res.data.challenge };
    }
    // La sesion queda en la cookie HttpOnly fijada por el backend; ya no se
    // guarda el JWT en localStorage (evita su robo por XSS).
    const data = res.data as { user: AuthUser };
    setUser(data.user);
    return { twoFactor: false };
  }

  /** Segundo paso: canjea el reto + codigo TOTP/respaldo por la sesion. */
  async function loginVerify2fa(challenge: string, code: string): Promise<void> {
    const res = await api.post<{ user: AuthUser }>('/auth/login/2fa', {
      challenge,
      code,
    });
    setUser(res.data.user);
  }

  function logout(): void {
    // Limpia la cookie de sesion en el servidor y cualquier token legado local.
    void api.post('/auth/logout').catch(() => undefined);
    tokenStorage.clear();
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, loginVerify2fa, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth debe usarse dentro de <AuthProvider>');
  return ctx;
}

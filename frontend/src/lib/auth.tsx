/**
 * Contexto de autenticacion del frontend.
 * Mantiene el usuario actual, gestiona login/logout y restaura sesion al cargar.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
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
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Al montar: si hay token, intenta recuperar el perfil
  useEffect(() => {
    const token = tokenStorage.get();
    if (!token) {
      setLoading(false);
      return;
    }
    api
      .get<{ user: AuthUser }>('/auth/me')
      .then((res) => setUser(res.data.user))
      .catch(() => tokenStorage.clear())
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string): Promise<void> {
    const res = await api.post<{ user: AuthUser; token: string }>('/auth/login', {
      email,
      password,
    });
    tokenStorage.set(res.data.token);
    setUser(res.data.user);
  }

  function logout(): void {
    tokenStorage.clear();
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth debe usarse dentro de <AuthProvider>');
  return ctx;
}

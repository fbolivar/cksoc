/**
 * Cliente HTTP del frontend.
 * Usa baseURL "/api" (mismo origen: Vite proxy en dev, Nginx en prod).
 * Inyecta el JWT guardado en localStorage en cada peticion.
 */
import axios from 'axios';

const TOKEN_KEY = 'soc_pnnc_token';

export const api = axios.create({
  baseURL: '/api',
  timeout: 15_000,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (error) => {
    // Token expirado/invalido -> limpiar sesion
    if (error.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
    }
    return Promise.reject(error);
  }
);

export const tokenStorage = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

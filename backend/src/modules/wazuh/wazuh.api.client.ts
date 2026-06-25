/**
 * Cliente de la Wazuh API REST (gestion) en :55000.
 * Autentica con Basic Auth para obtener un JWT y lo cachea hasta que expira.
 * Usado para el estado y listado de agentes (Fase 2).
 */
import axios, { type AxiosInstance } from 'axios';
import https from 'node:https';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

let client: AxiosInstance | null = null;
let token: string | null = null;
let tokenExpiresAt = 0; // epoch ms

function baseClient(): AxiosInstance {
  if (client) return client;
  if (!env.WAZUH_API_URL || !env.WAZUH_API_USER || !env.WAZUH_API_PASSWORD) {
    throw new HttpError(
      503,
      'Wazuh API no configurada. Define WAZUH_API_URL, WAZUH_API_USER y WAZUH_API_PASSWORD en el .env'
    );
  }
  client = axios.create({
    baseURL: env.WAZUH_API_URL,
    timeout: 10_000,
    httpsAgent: new https.Agent({ rejectUnauthorized: env.WAZUH_TLS_REJECT_UNAUTHORIZED }),
  });
  return client;
}

/** Obtiene (y cachea) un token JWT de la Wazuh API. */
async function getToken(): Promise<string> {
  const now = Date.now();
  if (token && now < tokenExpiresAt) return token;

  const c = baseClient();
  try {
    const { data } = await c.post<string>(
      '/security/user/authenticate?raw=true',
      undefined,
      {
        auth: { username: env.WAZUH_API_USER!, password: env.WAZUH_API_PASSWORD! },
        responseType: 'text',
      }
    );
    token = String(data).trim();
    // El token de Wazuh dura ~900s; renovamos a los 14 min por margen.
    tokenExpiresAt = now + 14 * 60_000;
    return token;
  } catch (err) {
    mapApiError(err);
  }
}

/** GET autenticado contra la Wazuh API, devolviendo el campo `data`. */
export async function wazuhApiGet<T = unknown>(
  path: string,
  params?: Record<string, string | number>
): Promise<T> {
  const c = baseClient();
  const jwt = await getToken();
  try {
    const { data } = await c.get<{ data: T; error: number }>(path, {
      headers: { Authorization: `Bearer ${jwt}` },
      params,
    });
    return data.data;
  } catch (err) {
    // Si el token expiro (401), reintenta una vez con token nuevo.
    const e = err as { response?: { status: number } };
    if (e.response?.status === 401) {
      token = null;
      const jwt2 = await getToken();
      const { data } = await c.get<{ data: T }>(path, {
        headers: { Authorization: `Bearer ${jwt2}` },
        params,
      });
      return data.data;
    }
    mapApiError(err);
  }
}

function mapApiError(err: unknown): never {
  if (err instanceof HttpError) throw err;
  const e = err as { code?: string; response?: { status: number } };
  if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT' || e.code === 'EHOSTUNREACH') {
    throw new HttpError(502, 'No se pudo conectar a la Wazuh API (.5:55000).');
  }
  if (e.response?.status === 401) {
    throw new HttpError(502, 'Credenciales de la Wazuh API invalidas');
  }
  throw new HttpError(502, 'Error consultando la Wazuh API');
}

/**
 * Cliente HTTP hacia el Wazuh Indexer (OpenSearch).
 * - Usa Basic Auth con las credenciales del .env.
 * - Acepta el certificado self-signed de Wazuh segun WAZUH_TLS_REJECT_UNAUTHORIZED.
 * - Falla con un error claro si faltan las credenciales (Fase 1 puede arrancar sin ellas).
 */
import axios, { type AxiosInstance } from 'axios';
import https from 'node:https';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

let cached: AxiosInstance | null = null;

export function getIndexerClient(): AxiosInstance {
  if (cached) return cached;

  if (!env.WAZUH_INDEXER_URL || !env.WAZUH_INDEXER_USER || !env.WAZUH_INDEXER_PASSWORD) {
    throw new HttpError(
      503,
      'Wazuh Indexer no configurado. Define WAZUH_INDEXER_URL, WAZUH_INDEXER_USER y WAZUH_INDEXER_PASSWORD en el .env'
    );
  }

  cached = axios.create({
    baseURL: env.WAZUH_INDEXER_URL,
    auth: {
      username: env.WAZUH_INDEXER_USER,
      password: env.WAZUH_INDEXER_PASSWORD,
    },
    timeout: 10_000,
    httpsAgent: new https.Agent({
      rejectUnauthorized: env.WAZUH_TLS_REJECT_UNAUTHORIZED,
    }),
  });

  return cached;
}

let statesCached: AxiosInstance | null = null;

/**
 * Cliente para los indices de ESTADO (wazuh-states-*: vulnerabilidades e
 * inventario). Usa las credenciales admin del Indexer si estan definidas
 * (algunos roles de solo-lectura no alcanzan estos indices); si no, reutiliza
 * el cliente regular.
 */
export function getStatesClient(): AxiosInstance {
  if (statesCached) return statesCached;
  if (!env.INDEXER_ADMIN_USER || !env.INDEXER_ADMIN_PASS || !env.WAZUH_INDEXER_URL) {
    return getIndexerClient();
  }
  statesCached = axios.create({
    baseURL: env.WAZUH_INDEXER_URL,
    auth: { username: env.INDEXER_ADMIN_USER, password: env.INDEXER_ADMIN_PASS },
    timeout: 10_000,
    httpsAgent: new https.Agent({ rejectUnauthorized: env.WAZUH_TLS_REJECT_UNAUTHORIZED }),
  });
  return statesCached;
}

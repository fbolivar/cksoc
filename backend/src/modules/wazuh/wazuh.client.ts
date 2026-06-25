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

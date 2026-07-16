/**
 * Carga y validacion de variables de entorno con zod.
 * Si falta una variable obligatoria, la app falla al arrancar (fail-fast).
 * Las credenciales de Wazuh/SMTP/Telegram son opcionales en Fase 1:
 * el endpoint que las necesite avisara con un error claro si no estan.
 */
import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

// Convierte "true"/"false"/"1"/"0" a booleano
const boolish = z
  .string()
  .transform((v) => v === 'true' || v === '1')
  .pipe(z.boolean());

const schema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(4000),
  CORS_ORIGIN: z.string().default('*'),

  // --- PostgreSQL (obligatorio) ---
  DATABASE_URL: z.string().min(1, 'DATABASE_URL es obligatoria'),

  // --- Auth (obligatorio) ---
  JWT_SECRET: z.string().min(16, 'JWT_SECRET debe tener al menos 16 caracteres'),
  JWT_EXPIRES_IN: z.string().default('8h'),

  // --- Respaldos de la base de datos (.pnnc) ---
  BACKUP_DIR: z.string().optional(), // por defecto: <home>/soc-pnnc-backups
  BACKUP_RETENTION: z.coerce.number().default(14), // cuantos respaldos automaticos conservar
  BACKUP_CRON: z.string().default('30 2 * * *'), // diario 02:30

  // --- Wazuh Indexer (OpenSearch) - opcional hasta tener credenciales ---
  WAZUH_INDEXER_URL: z.string().optional(),
  WAZUH_INDEXER_USER: z.string().optional(),
  WAZUH_INDEXER_PASSWORD: z.string().optional(),
  WAZUH_ALERTS_INDEX: z.string().default('wazuh-alerts-*'),

  // --- Wazuh API REST (gestion) - para fases siguientes ---
  WAZUH_API_URL: z.string().optional(),
  WAZUH_API_USER: z.string().optional(),
  WAZUH_API_PASSWORD: z.string().optional(),

  // TLS self-signed de Wazuh: en redes internas suele ser necesario "false"
  WAZUH_TLS_REJECT_UNAUTHORIZED: boolish.default('false'),

  // --- Notificaciones (Fase 3) - opcional ---
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().optional(),
  SMTP_SECURE: boolish.default('false'),
  SMTP_USER: z.string().optional(),
  // App Password de Gmail. SMTP_PASS es el nombre preferido; SMTP_PASSWORD se
  // mantiene por compatibilidad. Quitar espacios al pegar la clave de 16 digitos.
  SMTP_PASS: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().optional(),
  TELEGRAM_BOT_TOKEN: z.string().optional(),

  // --- Motor de notificaciones por correo (umbrales + anti-flood + digest) ---
  ALERT_RECIPIENTS: z.string().default(''), // coma-separado
  NOTIFY_IMMEDIATE_MIN_LEVEL: z.coerce.number().default(12), // criticas inmediatas
  NOTIFY_DIGEST_MIN_LEVEL: z.coerce.number().default(7), // nunca <7 por correo
  NOTIFY_FLOOD_MINUTES: z.coerce.number().default(30), // anti-flood misma regla+origen
  NOTIFY_DAILY_CAP: z.coerce.number().default(200), // tope de seguridad de cuota
  DIGEST_CRON: z.string().default('0 8 * * *'), // 8:00
  DIGEST_TZ: z.string().default('America/Bogota'),
  NOTIFY_BRUTEFORCE_RULES: z.string().default('100031,100036'),
  NOTIFY_ABUSE_MIN_SCORE: z.coerce.number().default(50),
  NOTIFY_POLL_SECONDS: z.coerce.number().default(60),
  PUBLIC_DASHBOARD_URL: z.string().default('http://192.168.50.4'),
  // Reglas con falsos positivos conocidos a excluir del conteo de INCIDENTES
  // del reporte ejecutivo (datos historicos ya indexados antes del tuning).
  REPORT_EXCLUDE_RULES: z.string().default('92213,92217'),

  // --- Reportes (Fase 4) ---
  REPORT_DIR: z.string().default('./reports'),
  REPORT_SCHEDULE_ENABLED: boolish.default('true'),
  REPORT_SCHEDULE_CRON: z.string().default('0 7 * * *'), // diario 07:00
  REPORT_SCHEDULE_RANGE: z.string().default('24h'),
  REPORT_EMAIL_TO: z.string().optional(), // correos separados por coma (opcional)
  // Ruta del ejecutable de Chromium (si no, Puppeteer usa el suyo)
  PUPPETEER_EXECUTABLE_PATH: z.string().optional(),

  // --- Geolocalizacion / Mapa de ataques ---
  GEOIP_DB_PATH: z.string().default('/opt/soc-app/data/GeoLite2-City.mmdb'),
  ATTACKS_CACHE_SECONDS: z.coerce.number().default(30),

  // --- Threat Intel (AbuseIPDB) ---
  ABUSEIPDB_API_KEY: z.string().optional(),
  // Tope diario de consultas a AbuseIPDB (free tier ~1000/dia); deja margen.
  ABUSEIPDB_DAILY_CAP: z.coerce.number().default(900),
  // Score de AbuseIPDB a partir del cual una IP se considera "ataque externo".
  ATTACKS_ABUSE_THRESHOLD: z.coerce.number().default(25),
  // Maximo de origenes a enriquecer con reputacion por consulta (cuota free ~1000/dia).
  ATTACKS_ENRICH_MAX: z.coerce.number().default(60),

  // --- Respuesta semi-automatica (FortiGate) ---
  FORTIGATE_HOST: z.string().optional(), // ej: 192.168.50.1
  FORTIGATE_API_TOKEN: z.string().optional(),
  FORTIGATE_BLOCKLIST_GROUP: z.string().default('WAZUH_BLOCKLIST'),
  FORTIGATE_TLS_REJECT_UNAUTHORIZED: boolish.default('false'),
  // IPs publicas criticas que NUNCA se pueden bloquear (coma-separadas):
  // gateway, DNS, IP publica de la entidad, IPs de admins, etc.
  RESPONSE_WHITELIST_IPS: z.string().default(''),

  // --- Salud del SIEM ---
  // Usuario admin del Indexer (necesario para cluster:monitor / disco).
  INDEXER_ADMIN_USER: z.string().optional(),
  INDEXER_ADMIN_PASS: z.string().optional(),
  HEALTH_EXPECTED_AGENTS: z.coerce.number().default(5),
  HEALTH_AGENT_STALE_MIN: z.coerce.number().default(10),
  HEALTH_DISK_WARN: z.coerce.number().default(80),
  HEALTH_DISK_CRIT: z.coerce.number().default(90),
  HEALTH_ALERTFLOW_MIN: z.coerce.number().default(2),
  HEALTH_ALERTFLOW_WINDOW_MIN: z.coerce.number().default(30),
  HEALTH_POLL_SECONDS: z.coerce.number().default(120),
  HEALTH_CRITICAL_PROCS: z.string().default('wazuh-analysisd,wazuh-remoted,wazuh-db,wazuh-modulesd'),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('❌ Variables de entorno invalidas:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
export type Env = typeof env;

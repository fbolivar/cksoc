/**
 * Punto de entrada del backend HexWatch.
 * - Express con seguridad (helmet, cors, rate-limit)
 * - Healthcheck con estado de la base de datos
 * - Rutas: /api/auth, /api/wazuh
 * - Servidor HTTP + Socket.io (preparado para tiempo real en Fase 2)
 */
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { pinoHttp } from 'pino-http';
import { createServer } from 'node:http';
import { Server as SocketServer } from 'socket.io';

import { env } from './config/env';
import { pingDb } from './config/db';
import { logger } from './config/logger';
import { apiLimiter } from './middleware/rateLimit';
import { authRouter } from './modules/auth/auth.routes';
import { wazuhRouter } from './modules/wazuh/wazuh.routes';
import { notificationsRouter } from './modules/notifications/notifications.routes';
import { reportsRouter } from './modules/reports/reports.routes';
import { executiveRouter } from './modules/reports/executive/exec.routes';
import { usersRouter } from './modules/users/users.routes';
import { systemRouter } from './modules/system/system.routes';
import { attacksRouter } from './modules/attacks/attacks.routes';
import { responseRouter } from './modules/response/response.routes';
import { healthRouter } from './modules/health/health.routes';
import { startHealthMonitor } from './modules/health/health.monitor';
import { vulnRouter } from './modules/vulnerabilities/vuln.routes';
import { mitreRouter } from './modules/mitre/mitre.routes';
import { scaRouter } from './modules/sca/sca.routes';
import { fimRouter } from './modules/fim/fim.routes';
import { hygieneRouter } from './modules/hygiene/hygiene.routes';
import { complianceRouter } from './modules/compliance/compliance.routes';
import { overviewRouter } from './modules/overview/overview.routes';
import { startOverviewWarmup } from './modules/overview/overview.warmup';
import { assetsRouter } from './modules/assets/assets.routes';
import { incidentsRouter } from './modules/incidents/incidents.routes';
import { backupsRouter } from './modules/backups/backups.routes';
import { startBackupScheduler } from './modules/backups/backups.scheduler';
import { auditRouter } from './modules/audit/audit.routes';
import { metricsRouter } from './modules/metrics/metrics.routes';
import { huntRouter } from './modules/hunt/hunt.routes';
import { savedHuntRouter } from './modules/hunt/saved.routes';
import { startSavedHuntScheduler } from './modules/hunt/saved.service';
import { playbooksRouter } from './modules/playbooks/playbooks.routes';
import { riskRouter } from './modules/risk/risk.routes';
import { velociraptorRouter } from './modules/velociraptor/velociraptor.routes';
import { setIo } from './modules/realtime/bus';
import { startMetricsBroadcast } from './modules/realtime/metrics';
import { startScheduler } from './modules/notifications/scheduler';
import { startAlertWatcher } from './modules/notifications/alertwatcher';
import { startDigestScheduler } from './modules/notifications/digest.service';
import { startReportScheduler } from './modules/reports/report.scheduler';
import { closePdfEngine } from './modules/reports/pdf.service';
import { initGeoIp } from './modules/geo/geoip.service';
import { startAttacksBroadcast } from './modules/attacks/attacks.broadcast';

const app = express();

// Detras de Nginx (un solo reverse proxy en el mismo host): confiar en el
// primer salto para que req.ip use el X-Forwarded-For real y el rate-limit
// cuente por IP de cliente (evita ERR_ERL_UNEXPECTED_X_FORWARDED_FOR).
app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN.split(',') }));
app.use(express.json({ limit: '1mb' }));

// Logging estructurado de peticiones (omite el healthcheck para no inundar).
app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === '/health' } }));

// Healthcheck (publico) — valida la conexion a Postgres
app.get('/health', async (_req, res) => {
  const db = await pingDb();
  res.status(db ? 200 : 503).json({
    status: db ? 'ok' : 'degraded',
    db: db ? 'ok' : 'down',
    service: 'hexwatch-backend',
    timestamp: new Date().toISOString(),
  });
});

// API con rate limiting general
app.use('/api', apiLimiter);
app.use('/api/auth', authRouter);
app.use('/api/wazuh', wazuhRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/reports/executive', executiveRouter); // antes de /api/reports
app.use('/api/reports', reportsRouter);
app.use('/api/users', usersRouter);
app.use('/api/system', systemRouter);
app.use('/api/attacks', attacksRouter);
app.use('/api/response', responseRouter);
app.use('/api/health', healthRouter);
app.use('/api/vulnerabilities', vulnRouter);
app.use('/api/mitre', mitreRouter);
app.use('/api/sca', scaRouter);
app.use('/api/fim', fimRouter);
app.use('/api/hygiene', hygieneRouter);
app.use('/api/compliance', complianceRouter);
app.use('/api/overview', overviewRouter);
app.use('/api/assets', assetsRouter);
app.use('/api/incidents', incidentsRouter);
app.use('/api/backups', backupsRouter);
app.use('/api/audit', auditRouter);
app.use('/api/metrics', metricsRouter);
app.use('/api/hunt/saved', savedHuntRouter); // antes de /api/hunt (mas especifico)
app.use('/api/hunt', huntRouter);
app.use('/api/playbooks', playbooksRouter);
app.use('/api/risk', riskRouter);
app.use('/api/velociraptor', velociraptorRouter);

// 404 para rutas /api desconocidas
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// Servidor HTTP + WebSocket (Socket.io listo para Fase 2)
const httpServer = createServer(app);
const io = new SocketServer(httpServer, {
  cors: { origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN.split(',') },
});
setIo(io); // el bus permite emitir eventos (notification:new) desde cualquier modulo

io.on('connection', (socket) => {
  socket.on('disconnect', () => {
    /* cliente desconectado */
  });
});

// Difusion de metricas en vivo (poll al Indexer cada 15s)
startMetricsBroadcast(io);

// Cache del Resumen Ejecutivo siempre caliente (evita esperas en frio)
startOverviewWarmup();

// Scheduler de notificaciones (evaluacion de reglas cada minuto)
startScheduler();

// Motor de correo: vigilante de alertas inmediatas + resumen diario
startAlertWatcher();
startDigestScheduler();

// Scheduler de reporte programado (diario)
startReportScheduler();

// Respaldo automatico diario de la base de datos (.pnnc) + retencion
startBackupScheduler();

// Cacerías guardadas con alerta por umbral (revisa cada minuto las que tocan)
startSavedHuntScheduler();

// Monitor de Salud del SIEM (quien vigila al vigilante)
startHealthMonitor();

// Geolocalizacion (carga GeoLite2) + emisor de ataques en vivo
void initGeoIp().then(() => startAttacksBroadcast(io));

// Cierre limpio del navegador de Puppeteer
process.on('SIGTERM', () => void closePdfEngine());
process.on('SIGINT', () => void closePdfEngine());

// Escuchar solo en loopback: Nginx (reverse proxy) llega por 127.0.0.1:4000.
// Evita exponer la API directamente a la red saltandose el proxy/TLS.
httpServer.listen(env.PORT, '127.0.0.1', () => {
  logger.info({ port: env.PORT, host: '127.0.0.1', env: env.NODE_ENV }, 'Backend HexWatch escuchando');
});

export { app, io };

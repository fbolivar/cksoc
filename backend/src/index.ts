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
import jwt from 'jsonwebtoken';
import { pinoHttp } from 'pino-http';
import { createServer } from 'node:http';
import { Server as SocketServer } from 'socket.io';

import { env } from './config/env';
import { pingDb, query } from './config/db';
import { getCookie } from './config/cookies';
import { logger } from './config/logger';
import type { JwtPayload } from './types';
import { apiLimiter } from './middleware/rateLimit';
import { licenseGate } from './middleware/license';
import { authRouter } from './modules/auth/auth.routes';
import { licenseRouter } from './modules/license/license.routes';
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
import { vulnRouter, startCveIntelScheduler } from './modules/vulnerabilities/vuln.routes';
import { mitreRouter } from './modules/mitre/mitre.routes';
import { scaRouter } from './modules/sca/sca.routes';
import { fimRouter } from './modules/fim/fim.routes';
import { hygieneRouter } from './modules/hygiene/hygiene.routes';
import { complianceRouter } from './modules/compliance/compliance.routes';
import { overviewRouter } from './modules/overview/overview.routes';
import { entityRiskRouter } from './modules/entity-risk/entity-risk.routes';
import { enrichmentRouter } from './modules/enrichment/enrichment.routes';
import { oncallRouter } from './modules/oncall/oncall.routes';
import { phishingRouter } from './modules/phishing/phishing.routes';
import { ndrRouter } from './modules/ndr/ndr.routes';
import { office365Router } from './modules/office365/o365.routes';
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
import { detectionRouter } from './modules/detection/detection.routes';
import { threatIntelRouter, startThreatIntelScheduler } from './modules/threatintel/threatintel.routes';
import { correlationRouter } from './modules/correlation/correlation.routes';
import { soarRouter, startSoarScheduler } from './modules/soar/soar.routes';
import { uebaRouter, startUebaScheduler } from './modules/ueba/ueba.routes';
import { copilotRouter } from './modules/copilot/copilot.routes';
import { actionCenterRouter } from './modules/action-center/action-center.routes';
import { startActionDigestScheduler } from './modules/action-center/action-center.scheduler';
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
app.use('/api/license', licenseRouter);
// Gate de licenciamiento: a partir de aquí, todo requiere licencia vigente.
app.use(licenseGate);
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
app.use('/api/entity-risk', entityRiskRouter);
app.use('/api/enrichment', enrichmentRouter);
app.use('/api/oncall', oncallRouter);
app.use('/api/phishing', phishingRouter);
app.use('/api/ndr', ndrRouter);
app.use('/api/office365', office365Router);
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
app.use('/api/detection', detectionRouter);
app.use('/api/threatintel', threatIntelRouter);
app.use('/api/correlation', correlationRouter);
app.use('/api/soar', soarRouter);
app.use('/api/ueba', uebaRouter);
app.use('/api/copilot', copilotRouter);
app.use('/api/action-center', actionCenterRouter);

// 404 para rutas /api desconocidas
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// Manejador de errores global: red de seguridad para cualquier error no
// capturado en un handler (evita peticiones colgadas / unhandledRejection).
// Loguea el detalle en el servidor y devuelve un mensaje generico al cliente.
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({ err, url: req.url }, 'Error no controlado en un handler');
  if (res.headersSent) return;
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Servidor HTTP + WebSocket (Socket.io listo para Fase 2)
const httpServer = createServer(app);
const io = new SocketServer(httpServer, {
  cors: { origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN.split(',') },
});

// Autenticacion del WebSocket: el socket difunde metricas del SIEM, mapa de
// ataques y notificaciones en vivo. Sin esto, cualquiera que alcance /socket.io
// recibiria datos del SOC. Se exige un JWT valido (cookie HttpOnly o handshake.auth)
// y ademas se comprueba la revocacion (token_version / cuenta activa).
io.use(async (socket, next) => {
  const token =
    (socket.handshake.auth?.token as string | undefined) ||
    getCookie(socket.handshake.headers.cookie, 'token') ||
    '';
  if (!token) { next(new Error('unauthorized')); return; }
  try {
    const payload = jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }) as JwtPayload;
    const rows = await query<{ token_version: number; is_active: boolean }>(
      'SELECT token_version, is_active FROM users WHERE id = $1',
      [payload.sub]
    );
    const u = rows[0];
    if (!u || !u.is_active || u.token_version !== payload.tv) {
      next(new Error('unauthorized'));
      return;
    }
    next();
  } catch {
    next(new Error('unauthorized'));
  }
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

// Threat Intelligence: refresco diario de feeds de IOCs (03:15)
startThreatIntelScheduler();

// SOAR: motor de respuesta automatizada (evalúa reglas cada 3 min)
startSoarScheduler();

// Digest periódico del Centro de Acción por Telegram (pendientes de todos los módulos)
startActionDigestScheduler();

// UEBA: motor de analítica de comportamiento (escanea cada 15 min)
startUebaScheduler();

// Inteligencia de CVEs (CISA KEV diario + EPSS cada 6 h) para priorizar vulns
startCveIntelScheduler();

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

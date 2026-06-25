/**
 * Punto de entrada del backend SOC PNNC.
 * - Express con seguridad (helmet, cors, rate-limit)
 * - Healthcheck con estado de la base de datos
 * - Rutas: /api/auth, /api/wazuh
 * - Servidor HTTP + Socket.io (preparado para tiempo real en Fase 2)
 */
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { createServer } from 'node:http';
import { Server as SocketServer } from 'socket.io';

import { env } from './config/env';
import { pingDb } from './config/db';
import { apiLimiter } from './middleware/rateLimit';
import { authRouter } from './modules/auth/auth.routes';
import { wazuhRouter } from './modules/wazuh/wazuh.routes';
import { notificationsRouter } from './modules/notifications/notifications.routes';
import { reportsRouter } from './modules/reports/reports.routes';
import { usersRouter } from './modules/users/users.routes';
import { systemRouter } from './modules/system/system.routes';
import { startMetricsBroadcast } from './modules/realtime/metrics';
import { startScheduler } from './modules/notifications/scheduler';
import { startReportScheduler } from './modules/reports/report.scheduler';
import { closePdfEngine } from './modules/reports/pdf.service';

const app = express();

app.use(helmet());
app.use(cors({ origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN.split(',') }));
app.use(express.json({ limit: '1mb' }));

// Healthcheck (publico) — valida la conexion a Postgres
app.get('/health', async (_req, res) => {
  const db = await pingDb();
  res.status(db ? 200 : 503).json({
    status: db ? 'ok' : 'degraded',
    db: db ? 'ok' : 'down',
    service: 'soc-pnnc-backend',
    timestamp: new Date().toISOString(),
  });
});

// API con rate limiting general
app.use('/api', apiLimiter);
app.use('/api/auth', authRouter);
app.use('/api/wazuh', wazuhRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/users', usersRouter);
app.use('/api/system', systemRouter);

// 404 para rutas /api desconocidas
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// Servidor HTTP + WebSocket (Socket.io listo para Fase 2)
const httpServer = createServer(app);
const io = new SocketServer(httpServer, {
  cors: { origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN.split(',') },
});

io.on('connection', (socket) => {
  socket.on('disconnect', () => {
    /* cliente desconectado */
  });
});

// Difusion de metricas en vivo (poll al Indexer cada 15s)
startMetricsBroadcast(io);

// Scheduler de notificaciones (evaluacion de reglas cada minuto)
startScheduler();

// Scheduler de reporte programado (diario)
startReportScheduler();

// Cierre limpio del navegador de Puppeteer
process.on('SIGTERM', () => void closePdfEngine());
process.on('SIGINT', () => void closePdfEngine());

httpServer.listen(env.PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`🟢 Backend SOC PNNC escuchando en http://127.0.0.1:${env.PORT} (${env.NODE_ENV})`);
});

export { app, io };

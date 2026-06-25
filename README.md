# SOC PNNC — Dashboard de Monitoreo de Seguridad

Aplicacion web de monitoreo de seguridad (SOC Dashboard) para **Parques Nacionales
Naturales de Colombia (PNNC)**, integrada con un servidor **Wazuh** existente.
Todo es local y auto-hospedado (sin servicios en la nube).

## Arquitectura

```
soc-pnnc-dashboard/
├── backend/    Node.js + Express + TypeScript (proxy seguro a Wazuh, auth, API)
└── frontend/   React 18 + Vite + TypeScript + TailwindCSS (dashboard)
```

- **Base de datos local:** PostgreSQL 16 (`soc_pnnc`) — solo datos propios de la app.
  Las alertas NO se almacenan: se leen en vivo del Wazuh Indexer.
- **Autenticacion:** JWT + bcrypt. Roles: `admin`, `analista`, `lector`.
- **Integracion Wazuh:**
  - API REST `https://192.168.50.5:55000` (gestion — fases siguientes)
  - Indexer/OpenSearch `https://192.168.50.5:9200` (alertas, indice `wazuh-alerts-*`)
- **Produccion:** PM2 (backend) + Nginx (sirve el frontend y hace proxy `/api`).

## Infraestructura

| Servidor | IP | Rol |
|----------|-----|-----|
| App (este) | 192.168.50.4 | Frontend + Backend + PostgreSQL |
| Wazuh | 192.168.50.5 | API REST (:55000) + Indexer (:9200) |

## Requisitos

- Node.js 22+, PostgreSQL 16, Nginx, PM2

## Variables de entorno

Copia `backend/.env.example` a `backend/.env` y completa los valores
(credenciales de PostgreSQL, JWT, Wazuh Indexer/API, SMTP, Telegram).
**Nunca** subas el `.env` al repositorio.

## Arranque en desarrollo

```bash
# Backend (puerto 4000)
cd backend
npm install
npm run migrate        # aplica el esquema a PostgreSQL
npm run dev

# Frontend (puerto 5173, proxy /api -> 4000)
cd frontend
npm install
npm run dev
```

## Despliegue en produccion

```bash
# Backend
cd backend && npm install && npm run build
pm2 start ../ecosystem.config.js && pm2 save

# Frontend
cd frontend && npm install && npm run build   # genera frontend/dist
# Nginx sirve frontend/dist y hace proxy de /api al backend (puerto 4000)
```

## Endpoints (Fase 1)

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| GET | `/health` | Estado del servicio + base de datos |
| POST | `/api/auth/register` | Registrar usuario |
| POST | `/api/auth/login` | Iniciar sesion (devuelve JWT) |
| GET | `/api/auth/me` | Perfil del usuario autenticado |
| GET | `/api/wazuh/alerts/count?range=24h` | Conteo de alertas (Indexer) |
| GET | `/api/wazuh/alerts/by-severity?range=24h` | Conteo por nivel de severidad |

## Roadmap

- **Fase 1 (actual):** integracion end-to-end (login + conteo real de alertas).
- **Fase 2:** dashboard completo (severidad, agentes, MITRE, timeline, mapa de calor).
- **Fase 3:** notificaciones (correo + Telegram) con reglas configurables.
- **Fase 4:** reportes PDF (manuales y programados) con identidad PNNC.
- **Fase 5:** gestion de usuarios, configuracion y agentes.

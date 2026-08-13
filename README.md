# HexWatch — Plataforma SOC

**HexWatch** es una plataforma de operaciones de seguridad (SOC) web, local y
auto-hospedada (sin nube), construida sobre un stack **Wazuh** existente e
integrada con **FortiGate** y **Velociraptor**. Cubre el ciclo completo de un SOC
moderno: **detectar → afinar → enriquecer → correlacionar → responder y contener**.

> Marca visible: **HexWatch**. Nombres técnicos internos (paquetes, base de datos,
> procesos) conservan el identificador histórico `soc-pnnc`.

## Capacidades

### Visibilidad
- **Panel** en vivo (KPIs, severidad, línea de tiempo, top agentes, MITRE, mapa de
  calor, tira de salud del SIEM, widget de agentes por sede).
- **Resumen Ejecutivo** y **Riesgo · Ejecutivo**.
- **Explorador de Alertas** (búsqueda/filtros/detalle), **Mapa de ataques** (geo),
  **MITRE ATT&CK**, **Métricas SOC**.
- Actualización en tiempo real vía **Socket.io**.

### Amenazas y detección
- **Threat Hunting** (búsquedas ad-hoc + cacerías guardadas con alerta por umbral).
- **Detecciones** — reglas que más disparan (candidatas a falso positivo) y
  **supresión de FP desde la UI** (crea reglas de excepción en Wazuh sin editar XML).
- **Threat Intelligence** — feeds públicos de IOCs (abuse.ch) con refresco
  automático, IOCs manuales, y **cruce automático** de IPs maliciosas conocidas
  contra las alertas (Wazuh + FortiGate).
- **Correlación multi-fuente** — agrupa alertas por IP de origen para presentar
  **un caso** en vez de N alertas sueltas; detecta actividad vista por varias
  fuentes (FortiGate IPS + Wazuh) y permite crear un incidente unificado.

### Respuesta y DFIR
- **Incidentes/Casos** con bitácora, asignación y estados.
- **Respuesta** — bloqueo semi-automático de IPs en **FortiGate** (lista blanca,
  reputación AbuseIPDB) desde alertas, incidentes, coincidencias de IOC o correlación.
- **Playbooks (SOAR)**.
- **Velociraptor (DFIR)** — panel de clientes, lanzar artefactos, ver resultados y
  **contención de endpoint de 1 clic**: aislar / liberar host y triage rápido.

### Postura / Endpoints
- **Activos** (Asset 360), **Vulnerabilidades**, **Config. Assessment (SCA)**,
  **Integridad (FIM)**, **IT Hygiene**, **Cumplimiento**.

### Operación
- **Notificaciones** (motor de correo con reglas/umbrales), **Reportes** PDF
  (manuales y programados), **Salud del SIEM**, **Respaldos** de la BD, **Auditoría**,
  **Gestión de usuarios**.

## Seguridad
- **Autenticación:** JWT en **cookie HttpOnly** (`SameSite=strict`, `Secure` en
  producción), bcrypt (coste 12), revocación por `token_version`, **2FA TOTP**
  (secreto cifrado AES-256-GCM, códigos de respaldo hasheados y de consumo atómico).
- **Roles:** `admin`, `analista`, `lector` (RBAC).
- Backend solo en loopback tras Nginx; helmet, CORS con lista blanca, rate-limit,
  validación con zod, saneamiento anti-inyección (SQL parametrizado, `execFile`/
  arrays), CSV anti-formula-injection.

## Arquitectura

```
soc-pnnc/
├── backend/    Node.js + Express + TypeScript
│   └── src/modules/  auth, wazuh, detection, threatintel, correlation,
│                     response (FortiGate), velociraptor, incidents, alerts,
│                     vulnerabilities, sca, fim, hygiene, compliance, reports,
│                     notifications, health, assets, hunt, playbooks, risk, audit…
└── frontend/   React 18 + Vite + TypeScript + TailwindCSS
```

- **Base de datos local:** PostgreSQL — solo datos propios de la app (usuarios,
  incidentes, IOCs, cacerías, config…). Las alertas NO se almacenan: se leen en
  vivo del **Wazuh Indexer**.
- **Producción:** PM2 (proceso `soc-backend`) + Nginx (sirve el frontend y hace
  proxy de `/api` y `/socket.io` al backend).

## Integraciones

| Fuente | Uso |
|--------|-----|
| **Wazuh Indexer** (OpenSearch) | Alertas en vivo (`wazuh-alerts-*`) |
| **Wazuh API** (:55000) | Agentes, gestión de reglas (supresión de FP), reinicio |
| **FortiGate** | Syslog → Wazuh; bloqueo de IPs vía API |
| **Velociraptor** | DFIR: colecciones, resultados y contención de endpoint |
| **AbuseIPDB** | Reputación de IPs |
| **abuse.ch** (Feodo/SSLBL) | Feeds públicos de IOCs (Threat Intelligence) |

Las direcciones concretas de cada servidor se definen en el `.env` (no se
documentan aquí por seguridad).

## Requisitos
- Node.js 22+, PostgreSQL 16, Nginx, PM2.

## Variables de entorno
Copia `backend/.env.example` a `backend/.env` y completa los valores (PostgreSQL,
`JWT_SECRET`, Wazuh Indexer/API, FortiGate, AbuseIPDB, etc.). **Nunca** subas el
`.env` al repositorio.

## Desarrollo

```bash
# Backend (puerto 4000)
cd backend
npm install
npm run migrate        # aplica/actualiza el esquema en PostgreSQL (idempotente)
npm run dev

# Frontend (puerto 5173, proxy /api -> 4000)
cd frontend
npm install
npm run dev
```

Verificación local: `npm run typecheck`, `npm run lint`, `npm test` (en cada paquete).

## Despliegue en producción

```bash
# Backend
cd backend && npm install && npm run migrate && npm run build
pm2 restart soc-backend --update-env   # o: pm2 start ../ecosystem.config.js && pm2 save

# Frontend
cd frontend && npm install && npm run build   # genera frontend/dist
# Nginx sirve frontend/dist y hace proxy de /api y /socket.io al backend (:4000)
```

## Integración continua
`.github/workflows/ci.yml` ejecuta, en backend y frontend, `lint` + `typecheck` +
`test` (y `build` en el frontend), con un PostgreSQL efímero para las pruebas de
integración.

## Estructura del repositorio

```
backend/    API, integraciones y lógica de negocio (módulos por dominio)
frontend/   SPA React (páginas por dominio, componentes UI, libs de API)
infra/      configuración de despliegue
ops/        utilidades de operación
.github/    workflows de CI
```

-- =====================================================================
-- Esquema inicial de la base de datos local "soc_pnnc"
-- Solo datos PROPIOS de la app. Las alertas NO se guardan aqui:
-- se leen en vivo del Wazuh Indexer.
-- =====================================================================

-- Extension para UUIDs
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------
-- Roles del sistema (admin, analista, lector)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL UNIQUE,   -- admin | analista | lector
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Usuarios de la aplicacion
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,        -- bcrypt
    full_name     VARCHAR(255) NOT NULL,
    role_id       INTEGER NOT NULL REFERENCES roles(id),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ---------------------------------------------------------------------
-- Configuracion de alertas (reglas para disparar notificaciones).
-- Estructura preparada para Fase 3.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    conditions  JSONB NOT NULL DEFAULT '{}'::jsonb,  -- ej: { "min_level": 10, "rule_groups": [...] }
    channels    JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ej: ["email","telegram"]
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Fase 3: columnas adicionales de reglas de notificacion en alert_configs
-- ---------------------------------------------------------------------
ALTER TABLE alert_configs
  ADD COLUMN IF NOT EXISTS min_level         INTEGER NOT NULL DEFAULT 10,
  ADD COLUMN IF NOT EXISTS rule_groups       TEXT[]  NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS threshold         INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS window_minutes    INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS cooldown_minutes  INTEGER NOT NULL DEFAULT 15,
  ADD COLUMN IF NOT EXISTS email_recipients  TEXT[]  NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS telegram_chat_ids TEXT[]  NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS last_checked_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_triggered_at TIMESTAMPTZ;

-- ---------------------------------------------------------------------
-- Fase 3: historico/auditoria de notificaciones enviadas
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id       UUID REFERENCES alert_configs(id) ON DELETE SET NULL,
    rule_name     VARCHAR(255),
    channel       VARCHAR(20) NOT NULL,                 -- email | telegram
    recipients    TEXT[] NOT NULL DEFAULT '{}',
    matched_count INTEGER,
    status        VARCHAR(20) NOT NULL,                 -- sent | failed
    error         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notiflog_created ON notification_log(created_at DESC);

-- ---------------------------------------------------------------------
-- Motor de notificaciones por correo: anti-flood, contador diario, settings
-- ---------------------------------------------------------------------
ALTER TABLE notification_log
  ADD COLUMN IF NOT EXISTS tipo          VARCHAR(20),    -- immediate | digest | test | cap
  ADD COLUMN IF NOT EXISTS alert_rule_id VARCHAR(32),    -- rule.id de Wazuh
  ADD COLUMN IF NOT EXISTS origen        VARCHAR(64);    -- IP origen / agente

-- Contador diario de correos (tope de seguridad de cuota Gmail)
CREATE TABLE IF NOT EXISTS daily_counter (
    fecha       DATE PRIMARY KEY,
    enviados    INTEGER NOT NULL DEFAULT 0,
    cap_avisado BOOLEAN NOT NULL DEFAULT FALSE
);

-- Configuracion del motor (singleton)
CREATE TABLE IF NOT EXISTS notification_settings (
    id                INTEGER PRIMARY KEY DEFAULT 1,
    recipients        TEXT[]  NOT NULL DEFAULT '{}',
    immediate_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    digest_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    digest_hour       INTEGER NOT NULL DEFAULT 8,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notif_settings_singleton CHECK (id = 1)
);
INSERT INTO notification_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------
-- Respuesta semi-automatica: auditoria de acciones de bloqueo/desbloqueo
-- Toda accion sobre el FortiGate queda registrada (trazabilidad institucional).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS block_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip              VARCHAR(45) NOT NULL,
    accion          VARCHAR(10) NOT NULL,                 -- block | unblock
    motivo          TEXT,
    usuario_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    usuario_email   VARCHAR(255),                         -- snapshot por si se borra el usuario
    resultado       VARCHAR(20) NOT NULL,                 -- success | failed | rejected
    detalle         TEXT,                                 -- error o info adicional
    alerta_origen_id VARCHAR(255),                        -- id de la alerta de Wazuh, si aplica
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_block_actions_ip ON block_actions(ip);
CREATE INDEX IF NOT EXISTS idx_block_actions_created ON block_actions(created_at DESC);

-- ---------------------------------------------------------------------
-- Reporte ejecutivo mensual (Comite SGSI / ISO 27001)
-- ---------------------------------------------------------------------
-- Snapshot mensual de metricas para la seccion de tendencias
-- Nota: vuln_criticas y hardening_score se agregan via ALTER mas abajo (idempotente)
CREATE TABLE IF NOT EXISTS monthly_snapshots (
    mes                 VARCHAR(7) PRIMARY KEY,            -- YYYY-MM
    total_eventos       BIGINT  NOT NULL DEFAULT 0,
    incidentes_criticos INTEGER NOT NULL DEFAULT 0,
    incidentes_altos    INTEGER NOT NULL DEFAULT 0,
    ips_bloqueadas      INTEGER NOT NULL DEFAULT 0,
    top_amenazas        JSONB   NOT NULL DEFAULT '[]'::jsonb,
    postura_semaforo    VARCHAR(10) NOT NULL DEFAULT 'verde',
    generado_en         TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE monthly_snapshots ADD COLUMN IF NOT EXISTS vuln_criticas   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE monthly_snapshots ADD COLUMN IF NOT EXISTS hardening_score INTEGER NOT NULL DEFAULT 0;

-- Reportes ejecutivos generados (con estado y ediciones de Fernando)
CREATE TABLE IF NOT EXISTS executive_reports (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mes           VARCHAR(7) NOT NULL,                      -- YYYY-MM
    estado        VARCHAR(20) NOT NULL DEFAULT 'borrador',  -- borrador | revisado | enviado
    pdf_path      TEXT,
    datos_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    resumen_editado        TEXT,                            -- override del resumen ejecutivo
    recomendaciones_editadas TEXT,                          -- override de recomendaciones
    generado_por  UUID REFERENCES users(id) ON DELETE SET NULL,
    generado_en   TIMESTAMPTZ NOT NULL DEFAULT now(),
    enviado_en    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_exec_reports_mes ON executive_reports(mes);

-- ---------------------------------------------------------------------
-- Historico de reportes generados (Fase 4)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        VARCHAR(255) NOT NULL,
    type         VARCHAR(20)  NOT NULL DEFAULT 'manual',   -- manual | scheduled
    format       VARCHAR(10)  NOT NULL DEFAULT 'pdf',
    file_path    TEXT,
    params       JSONB NOT NULL DEFAULT '{}'::jsonb,       -- rango de fechas, filtros, etc.
    status       VARCHAR(20)  NOT NULL DEFAULT 'completed',-- pending | completed | failed
    generated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Suscripciones a notificaciones por usuario (Fase 3)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_subscriptions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel    VARCHAR(20) NOT NULL,                       -- email | telegram
    target     VARCHAR(255) NOT NULL,                      -- correo destino o chat_id de Telegram
    severities JSONB NOT NULL DEFAULT '[]'::jsonb,         -- ej: ["high","critical"]
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notification_subscriptions(user_id);

-- ---------------------------------------------------------------------
-- Salud del SIEM: bitacora de cambios de estado de los componentes
-- (agentes, manager, indexer, disco, flujo). Sirve para el historico/timeline
-- y para detectar transiciones (bueno->malo / malo->bueno).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS health_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    componente VARCHAR(40) NOT NULL,            -- agentes | manager | indexer | disco | flujo
    estado     VARCHAR(10) NOT NULL,            -- ok | warn | fail
    detalle    TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_log_comp_ts ON health_log(componente, ts DESC);

-- ---------------------------------------------------------------------
-- Seed de roles (idempotente)
-- ---------------------------------------------------------------------
INSERT INTO roles (name, description) VALUES
    ('admin',    'Acceso total: gestion de usuarios, configuracion y reportes'),
    ('analista', 'Operacion del SOC: alertas, notificaciones y reportes'),
    ('lector',   'Solo lectura del dashboard')
ON CONFLICT (name) DO NOTHING;

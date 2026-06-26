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
-- Seed de roles (idempotente)
-- ---------------------------------------------------------------------
INSERT INTO roles (name, description) VALUES
    ('admin',    'Acceso total: gestion de usuarios, configuracion y reportes'),
    ('analista', 'Operacion del SOC: alertas, notificaciones y reportes'),
    ('lector',   'Solo lectura del dashboard')
ON CONFLICT (name) DO NOTHING;

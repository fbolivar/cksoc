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
-- Gestion de incidentes/casos del SOC (ciclo de vida + timeline)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        VARCHAR(200) NOT NULL,
    description  TEXT,
    severity     VARCHAR(10)  NOT NULL DEFAULT 'media',     -- baja | media | alta | critica
    status       VARCHAR(15)  NOT NULL DEFAULT 'abierto',   -- abierto | en_curso | resuelto | cerrado
    assignee_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    source       JSONB NOT NULL DEFAULT '{}'::jsonb,        -- {alertId, index, ip, agent, ruleId}
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at DESC);

CREATE TABLE IF NOT EXISTS incident_notes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id  UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    author_name  VARCHAR(255),
    kind         VARCHAR(20) NOT NULL DEFAULT 'comment',    -- comment | system
    note         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_inc ON incident_notes(incident_id, created_at);

-- ---------------------------------------------------------------------
-- 2FA (TOTP) por usuario: secreto cifrado (AES-256-GCM), flag de
-- activacion y codigos de respaldo (hashes SHA-256, de un solo uso).
-- ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_backup_codes TEXT[];

-- Version de token para revocacion de sesiones: cada JWT lleva 'tv' y debe
-- coincidir con este valor. Al cambiar la contrasena o "cerrar todas las
-- sesiones" se incrementa, invalidando de inmediato los tokens anteriores.
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------
-- Seed de roles (idempotente)
-- ---------------------------------------------------------------------
INSERT INTO roles (name, description) VALUES
    ('admin',    'Acceso total: gestion de usuarios, configuracion y reportes'),
    ('analista', 'Operacion del SOC: alertas, notificaciones y reportes'),
    ('lector',   'Solo lectura del dashboard')
ON CONFLICT (name) DO NOTHING;

-- =====================================================================
-- Registro de auditoria: quien hizo que en la aplicacion (acciones de
-- usuario, incluidos inicios de sesion y fallidos). Complementa los logs
-- por dominio (block_actions, notification_log) con una traza unificada.
-- =====================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email  TEXT,
    action       TEXT NOT NULL,             -- login, login_failed, user_create, backup_create, ...
    target       TEXT,                      -- sobre que actuo (email, id, archivo)
    result       TEXT NOT NULL DEFAULT 'ok', -- ok | fail
    ip           TEXT,
    user_agent   TEXT,
    detail       JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_log (actor_email);

-- =====================================================================
-- SOAR / Playbooks: respuesta automatizada ante patrones de alerta.
-- Modo 'simulacion' (por defecto) registra lo que HARIA sin ejecutar;
-- 'activo' ejecuta las acciones. Seguridad: enabled=false por defecto,
-- cooldown por objetivo, y block_ip respeta la lista blanca existente.
-- =====================================================================
CREATE TABLE IF NOT EXISTS playbooks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(120) NOT NULL,
    description  TEXT,
    enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    mode         VARCHAR(12) NOT NULL DEFAULT 'simulacion',  -- simulacion | activo
    conditions   JSONB NOT NULL DEFAULT '{}'::jsonb,          -- {minLevel, ruleIds[], mitre[], agents[], groups[]}
    actions      JSONB NOT NULL DEFAULT '[]'::jsonb,          -- [{type, params}]
    cooldown_min INTEGER NOT NULL DEFAULT 30,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id  UUID REFERENCES playbooks(id) ON DELETE CASCADE,
    playbook_name VARCHAR(120),
    target       VARCHAR(255),            -- ip o agente sobre el que se actuo
    matched      JSONB,                   -- {level, ruleId, ip, agent, description}
    actions      JSONB,                   -- [{type, status, detail}]
    mode         VARCHAR(12) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_pb ON playbook_runs(playbook_id, created_at DESC);

-- =====================================================================
-- Cacerias guardadas (saved hunts) + alerta opcional por umbral.
-- =====================================================================
CREATE TABLE IF NOT EXISTS saved_hunts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(120) NOT NULL,
    query         JSONB NOT NULL,          -- {range, q, agent, ruleId, minLevel, srcip, mitre}
    alert_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    threshold     INTEGER NOT NULL DEFAULT 1,
    interval_min  INTEGER NOT NULL DEFAULT 15,
    last_run      TIMESTAMPTZ,
    last_count    INTEGER,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
-- Threat Intelligence: indicadores de compromiso (IOCs) y estado de feeds.
-- =====================================================================
CREATE TABLE IF NOT EXISTS iocs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type      VARCHAR(16)  NOT NULL,            -- ip | domain | url | md5 | sha1 | sha256
    value         VARCHAR(1024) NOT NULL,
    source        VARCHAR(120) NOT NULL DEFAULT 'manual',  -- nombre del feed o 'manual'
    description   TEXT,
    tags          TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    added_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    last_match_at TIMESTAMPTZ,
    match_count   INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(ioc_type, value);
-- Threat Intel: confianza (0-100) y frescura (aging). last_seen_feed = última vez
-- que un feed reportó el IOC; NULL para IOCs manuales (no envejecen).
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS confidence     SMALLINT NOT NULL DEFAULT 50;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS last_seen_feed TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_iocs_enabled ON iocs(enabled);

CREATE TABLE IF NOT EXISTS ioc_feeds (
    name        VARCHAR(120) PRIMARY KEY,
    last_run_at TIMESTAMPTZ,
    last_count  INTEGER NOT NULL DEFAULT 0,
    last_status VARCHAR(255)
);

-- =====================================================================
-- SOAR: reglas de respuesta automatizada y su registro de ejecuciones.
-- =====================================================================
CREATE TABLE IF NOT EXISTS automation_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           VARCHAR(160) NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    trigger_type   VARCHAR(32) NOT NULL,               -- ioc_ip_match | rule_level | rule_id
    trigger_config JSONB NOT NULL DEFAULT '{}'::jsonb, -- {minLevel, group, ruleId}
    action         VARCHAR(32) NOT NULL,               -- block_ip | isolate_host | create_incident
    mode           VARCHAR(16) NOT NULL DEFAULT 'approval', -- auto | approval
    dry_run        BOOLEAN NOT NULL DEFAULT FALSE,
    cooldown_min   INTEGER NOT NULL DEFAULT 60,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    last_triggered_at TIMESTAMPTZ,
    trigger_count  INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS automation_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id      UUID REFERENCES automation_rules(id) ON DELETE CASCADE,
    rule_name    VARCHAR(160),
    entity       VARCHAR(255) NOT NULL,     -- IP o host afectado
    action       VARCHAR(32) NOT NULL,
    status       VARCHAR(16) NOT NULL,      -- pending | executed | failed | skipped | rejected
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_autoevents_rule_entity ON automation_events(rule_id, entity, created_at);
CREATE INDEX IF NOT EXISTS idx_autoevents_status ON automation_events(status, created_at);

-- =====================================================================
-- UEBA: analítica de comportamiento de usuarios/entidades. El motor
-- construye una línea base por usuario (hosts, horario, países) y detecta
-- desviaciones (host nuevo, fuera de horario, pico de fallos, viaje
-- imposible, país nuevo). Agnóstico de la fuente: hoy Wazuh, mañana M365.
-- =====================================================================
CREATE TABLE IF NOT EXISTS ueba_anomalies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detector    VARCHAR(32)  NOT NULL,   -- new_host | off_hours | auth_failure_spike | impossible_travel | new_country
    entity      VARCHAR(160) NOT NULL,   -- usuario/identidad
    entity_type VARCHAR(16)  NOT NULL DEFAULT 'user',
    severity    VARCHAR(16)  NOT NULL DEFAULT 'media',  -- baja | media | alta | critica
    score       INTEGER      NOT NULL DEFAULT 0,
    title       VARCHAR(240) NOT NULL,
    summary     TEXT,
    evidence    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    source      VARCHAR(16)  NOT NULL DEFAULT 'wazuh',   -- wazuh | m365
    status      VARCHAR(16)  NOT NULL DEFAULT 'open',    -- open | ack | dismissed
    dedup_key   VARCHAR(320) NOT NULL UNIQUE,            -- detector|entity|discriminador de ventana
    first_seen  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ack_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    ack_at      TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ueba_status ON ueba_anomalies(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_entity ON ueba_anomalies(entity, detector);

-- Configuración del motor UEBA (una sola fila, id = TRUE).
CREATE TABLE IF NOT EXISTS ueba_settings (
    id             BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    biz_start_hour SMALLINT NOT NULL DEFAULT 6,    -- inicio horario laboral (hora local Colombia)
    biz_end_hour   SMALLINT NOT NULL DEFAULT 21,   -- fin horario laboral
    include_weekend BOOLEAN NOT NULL DEFAULT FALSE, -- ¿el fin de semana cuenta como laboral?
    lookback_days  SMALLINT NOT NULL DEFAULT 30,   -- ventana de línea base
    recent_hours   SMALLINT NOT NULL DEFAULT 24,   -- ventana de detección
    fail_threshold SMALLINT NOT NULL DEFAULT 8,    -- fallos de auth para marcar pico
    impossible_kmh SMALLINT NOT NULL DEFAULT 900,  -- velocidad implícita para "viaje imposible"
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO ueba_settings (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;

-- =====================================================================
-- Inteligencia de CVEs: enriquece las vulnerabilidades detectadas por
-- Wazuh con señales de EXPLOTACIÓN REAL para priorizar por riesgo:
--   - CISA KEV: ¿la CVE está siendo explotada activamente en el mundo?
--   - EPSS (FIRST.org): probabilidad (0-1) de explotación en 30 días.
-- =====================================================================
CREATE TABLE IF NOT EXISTS cve_intel (
    cve        VARCHAR(32) PRIMARY KEY,
    in_kev     BOOLEAN NOT NULL DEFAULT FALSE,   -- en el catálogo CISA KEV
    kev_name   TEXT,
    kev_added  DATE,
    kev_due    DATE,
    epss       REAL,        -- probabilidad de explotación 0-1
    epss_pct   REAL,        -- percentil 0-1
    epss_at    TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cve_intel_kev ON cve_intel(in_kev) WHERE in_kev = TRUE;

CREATE TABLE IF NOT EXISTS cve_intel_feeds (
    name        VARCHAR(40) PRIMARY KEY,   -- 'cisa_kev' | 'epss'
    last_run_at TIMESTAMPTZ,
    last_count  INTEGER NOT NULL DEFAULT 0,
    last_status VARCHAR(255)
);

-- =====================================================================
-- Madurez de casos: SLA por severidad + marca de reconocimiento para
-- medir MTTA (time to acknowledge) y MTTR (time to resolve).
-- =====================================================================
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS sla_policy (
    severity        VARCHAR(10) PRIMARY KEY,   -- critica | alta | media | baja
    ack_minutes     INTEGER NOT NULL,          -- objetivo de reconocimiento
    resolve_minutes INTEGER NOT NULL           -- objetivo de resolución
);
INSERT INTO sla_policy (severity, ack_minutes, resolve_minutes) VALUES
    ('critica', 15,  240),
    ('alta',    30,  480),
    ('media',   120, 1440),
    ('baja',    480, 4320)
ON CONFLICT (severity) DO NOTHING;

-- Turnos de guardia (on-call): quién es responsable en cada franja horaria.
-- Alimenta el escalamiento de incidentes (notifica al analista de guardia).
CREATE TABLE IF NOT EXISTS oncall_shifts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starts_at   TIMESTAMPTZ NOT NULL,
    ends_at     TIMESTAMPTZ NOT NULL,
    note        TEXT,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oncall_range_valid CHECK (ends_at > starts_at)
);
CREATE INDEX IF NOT EXISTS idx_oncall_range ON oncall_shifts (starts_at, ends_at);

-- Factor humano: resultados de campañas de phishing / concienciación. Alimenta el
-- dominio "factor_humano" del Resumen Ejecutivo (hasta ahora sin fuente).
CREATE TABLE IF NOT EXISTS phishing_campaigns (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(200) NOT NULL,
    run_date     DATE NOT NULL,
    sent         INTEGER NOT NULL DEFAULT 0,
    clicked      INTEGER NOT NULL DEFAULT 0,
    reported     INTEGER NOT NULL DEFAULT 0,
    trained_pct  SMALLINT NOT NULL DEFAULT 0,
    note         TEXT,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_phishing_date ON phishing_campaigns (run_date DESC);

-- ---------------------------------------------------------------------
-- Licenciamiento (código de activación firmado Ed25519). Fila única id=1.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS license (
    id           INTEGER PRIMARY KEY DEFAULT 1,
    code         TEXT        NOT NULL,
    customer     TEXT,
    license_id   TEXT,
    issued_at    TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_by UUID,
    CONSTRAINT license_singleton CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS license_state (
    id           INTEGER PRIMARY KEY DEFAULT 1,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT license_state_singleton CHECK (id = 1)
);

SET search_path TO workshop;

-- ============================================================
-- 1. SEKWENCJE
-- ============================================================
CREATE SEQUENCE IF NOT EXISTS user_seq                  START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS user_session_seq          START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS message_category_seq      START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS message_seq               START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS alert_seq                 START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS alert_category_seq        START WITH 1 INCREMENT BY 1@@


-- ============================================================
-- 2. TABELE
-- ============================================================

CREATE TABLE IF NOT EXISTS app_user (
    id                          BIGINT        NOT NULL DEFAULT nextval('user_seq'),
    username                    VARCHAR(255)  NOT NULL UNIQUE,
    password_hash               VARCHAR(255)  NOT NULL,
    public_key                  TEXT          DEFAULT NULL,
    signing_public_key          TEXT          DEFAULT NULL,
    encrypted_private_key       TEXT          DEFAULT NULL,
    encrypted_signing_priv_key  TEXT          DEFAULT NULL,
    kdf_salt                    VARCHAR(64)   DEFAULT NULL,
    account_status              VARCHAR(20)   NOT NULL DEFAULT 'ACTIVE',
    blocked_until               TIMESTAMP     DEFAULT NULL,
    block_reason                TEXT          DEFAULT NULL,
    PRIMARY KEY (id),
    CONSTRAINT chk_account_status CHECK (account_status IN ('ACTIVE', 'BLOCKED', 'SUSPENDED'))
)@@

CREATE TABLE IF NOT EXISTS user_session (
    id                  BIGINT        NOT NULL DEFAULT nextval('user_session_seq'),
    user_id             BIGINT        NOT NULL,
    session_token       VARCHAR(255)  NOT NULL UNIQUE,
    login_time          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time         TIMESTAMP     DEFAULT NULL,
    ip_address          VARCHAR(45)   DEFAULT NULL,
    user_agent          VARCHAR(512)  DEFAULT NULL,
    is_active           BOOLEAN       NOT NULL DEFAULT TRUE,
    invalidation_reason VARCHAR(100)  DEFAULT NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_user_session_user
        FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
)@@

CREATE TABLE IF NOT EXISTS message_category (
    id            BIGINT      NOT NULL DEFAULT nextval('message_category_seq'),
    category_name VARCHAR(50) NOT NULL UNIQUE,
    PRIMARY KEY (id)
)@@

INSERT INTO message_category (category_name)
VALUES ('STANDARD'), ('END_TO_END_ENCRYPTED')
ON CONFLICT (category_name) DO NOTHING@@


CREATE TABLE IF NOT EXISTS secret_message (
    id                BIGINT      NOT NULL DEFAULT nextval('message_seq'),
    sender_id         BIGINT      NOT NULL,
    receiver_id       BIGINT      NOT NULL,
    category_id       BIGINT      NOT NULL,
    encrypted_content TEXT        NOT NULL,
    secret_iv         VARCHAR(64) NOT NULL DEFAULT 'MIGRATED_NO_IV',
    secret_salt       VARCHAR(64) NOT NULL DEFAULT 'MIGRATED_NO_SALT',
    digital_signature TEXT        DEFAULT NULL,
    created_at        TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_message_sender
        FOREIGN KEY (sender_id)   REFERENCES app_user(id)        ON DELETE CASCADE,
    CONSTRAINT fk_message_receiver
        FOREIGN KEY (receiver_id) REFERENCES app_user(id)        ON DELETE CASCADE,
    CONSTRAINT fk_message_category
        FOREIGN KEY (category_id) REFERENCES message_category(id)
)@@

CREATE TABLE IF NOT EXISTS security_alert (
    id             BIGINT      NOT NULL DEFAULT nextval('alert_seq'),
    user_id        BIGINT      NOT NULL,
    severity_level VARCHAR(10) NOT NULL,
    alert_type     VARCHAR(50) NOT NULL,
    description    TEXT        NOT NULL,
    timestamp      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_alert_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    CONSTRAINT chk_severity_level CHECK (severity_level IN ('LOW', 'MEDIUM', 'HIGH')),
    CONSTRAINT chk_alert_type CHECK (alert_type IN (
        'BRUTE_FORCE',
        'LOGIN_AFTER_HOURS_LOW',
        'LOGIN_AFTER_HOURS_HIGH',
        'DLP_SENSITIVE_KEYWORD',
        'DLP_PESEL_PATTERN',
        'DLP_CARD_PATTERN',
        'DLP_LINK_DETECTED',
        'ESCALATION_AGGREGATED'
    ))
)@@


-- ============================================================
-- 3. INDEKSY
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_user_username              ON app_user(username)@@
CREATE INDEX IF NOT EXISTS idx_user_account_status        ON app_user(account_status)@@
CREATE INDEX IF NOT EXISTS idx_user_session_user          ON user_session(user_id)@@
CREATE INDEX IF NOT EXISTS idx_user_session_active        ON user_session(user_id, is_active)@@
CREATE INDEX IF NOT EXISTS idx_secret_message_sender      ON secret_message(sender_id)@@
CREATE INDEX IF NOT EXISTS idx_secret_message_receiver    ON secret_message(receiver_id)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_user        ON security_alert(user_id)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_timestamp   ON security_alert(timestamp)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_type        ON security_alert(alert_type)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_user_time   ON security_alert(user_id, timestamp DESC)@@


-- ============================================================
-- 4. WIDOKI
-- ============================================================

-- Aktywne alerty HIGH z ostatnich 24h (do monitoringu)
CREATE OR REPLACE VIEW v_active_security_alerts AS
SELECT
    sa.id,
    u.username,
    sa.alert_type,
    sa.description,
    sa.severity_level,
    sa.timestamp,
    u.account_status,
    u.blocked_until
FROM security_alert sa
         JOIN app_user u ON sa.user_id = u.id
WHERE sa.severity_level = 'HIGH'
  AND sa.timestamp >= NOW() - INTERVAL '24 hours'@@

-- Aktualnie zablokowane konta
CREATE OR REPLACE VIEW v_blocked_accounts AS
SELECT
    u.id,
    u.username,
    u.account_status,
    u.blocked_until,
    u.block_reason,
    COUNT(sa.id) AS alert_count_24h
FROM app_user u
         LEFT JOIN security_alert sa
                   ON sa.user_id = u.id
                       AND sa.timestamp >= NOW() - INTERVAL '24 hours'
WHERE u.account_status = 'BLOCKED'
GROUP BY u.id, u.username, u.account_status, u.blocked_until, u.block_reason@@


-- ============================================================
-- 5. FUNKCJE
-- ============================================================

-- Zlicza alerty danego poziomu dla użytkownika z ostatnich N minut
-- Używane przez Drools (eskalacja alertów)
CREATE OR REPLACE FUNCTION fn_count_recent_alerts_by_level(
    target_user_id   BIGINT,
    minutes_interval INT,
    level            VARCHAR(10)
    )
    RETURNS INT AS $$
DECLARE
alert_count INT;
BEGIN
SELECT COUNT(*) INTO alert_count
FROM security_alert
WHERE user_id       = target_user_id
  AND severity_level = level
  AND timestamp      >= NOW() - (minutes_interval || ' minutes')::INTERVAL;
RETURN alert_count;
END;
$$ LANGUAGE plpgsql@@

-- Oryginalna funkcja HIGH-only (USUNIETE)


-- Automatyczne odblokowywanie kont po upływie czasu blokady
-- Wywoływana przez scheduled task Spring lub cron w DB
CREATE OR REPLACE FUNCTION fn_unblock_expired_accounts()
RETURNS INT AS $$
DECLARE
unblocked_count INT;
BEGIN
UPDATE app_user
SET account_status = 'ACTIVE',
    blocked_until  = NULL,
    block_reason   = NULL
WHERE account_status = 'BLOCKED'
  AND blocked_until  IS NOT NULL
  AND blocked_until  <= NOW();

GET DIAGNOSTICS unblocked_count = ROW_COUNT;
RETURN unblocked_count;
END;
$$ LANGUAGE plpgsql@@

-- Funkcja czyszczenia starych logów
CREATE OR REPLACE FUNCTION fn_cleanup_old_audit_logs(days_to_keep INT)
RETURNS INT AS $$
DECLARE
deleted_sessions INT;
    deleted_alerts INT;
BEGIN
    -- Usuń tylko nieaktywne sesje starsze niż zadany czas
DELETE FROM user_session
WHERE is_active = FALSE
  AND logout_time < NOW() - (days_to_keep || ' days')::INTERVAL;
GET DIAGNOSTICS deleted_sessions = ROW_COUNT;

-- Usuń tylko mało znaczące alerty LOW (HIGH i MEDIUM trzymamy dla dowodów)
DELETE FROM security_alert
WHERE severity_level = 'LOW'
  AND timestamp < NOW() - (days_to_keep || ' days')::INTERVAL;
GET DIAGNOSTICS deleted_alerts = ROW_COUNT;

RETURN deleted_sessions + deleted_alerts;
END;
$$ LANGUAGE plpgsql@@
SET search_path TO workshop;

-- 1. TWORZENIE SEKWENCJI
CREATE SEQUENCE IF NOT EXISTS user_seq START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS user_session_seq START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS message_category_seq START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS message_seq START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS alert_seq START WITH 1 INCREMENT BY 1@@


-- 2. TWORZENIE TABEL
CREATE TABLE IF NOT EXISTS app_user (
    id BIGINT NOT NULL DEFAULT nextval('user_seq'),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
    )@@

CREATE TABLE IF NOT EXISTS user_session (
    id BIGINT NOT NULL DEFAULT nextval('user_session_seq'),
    user_id BIGINT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    login_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    PRIMARY KEY (id),
    CONSTRAINT fk_user_session_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
    )@@

CREATE TABLE IF NOT EXISTS message_category (
    id BIGINT NOT NULL DEFAULT nextval('message_category_seq'),
    category_name VARCHAR(50) NOT NULL UNIQUE,
    PRIMARY KEY (id)
    )@@

INSERT INTO message_category (category_name) VALUES ('STANDARD'), ('CONFIDENTIAL')
    ON CONFLICT (category_name) DO NOTHING@@

CREATE TABLE IF NOT EXISTS secret_message (
    id BIGINT NOT NULL DEFAULT nextval('message_seq'),
    sender_id BIGINT NOT NULL,
    receiver_id BIGINT NOT NULL,
    category_id BIGINT NOT NULL,
    encrypted_content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_message_sender FOREIGN KEY (sender_id) REFERENCES app_user(id) ON DELETE CASCADE,
    CONSTRAINT fk_message_receiver FOREIGN KEY (receiver_id) REFERENCES app_user(id) ON DELETE CASCADE,
    CONSTRAINT fk_message_category FOREIGN KEY (category_id) REFERENCES message_category(id)
    )@@

CREATE TABLE IF NOT EXISTS security_alert (
    id BIGINT NOT NULL DEFAULT nextval('alert_seq'),
    user_id BIGINT NOT NULL,
    description TEXT NOT NULL,
    severity_level VARCHAR(10) NOT NULL CHECK (severity_level IN ('LOW', 'MEDIUM', 'HIGH')),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_alert_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
    )@@


-- 3. INDEKSY OPTYMALIZACYJNE
CREATE INDEX IF NOT EXISTS idx_user_username ON app_user(username)@@
CREATE INDEX IF NOT EXISTS idx_user_session_user ON user_session(user_id)@@
CREATE INDEX IF NOT EXISTS idx_secret_message_sender ON secret_message(sender_id)@@
CREATE INDEX IF NOT EXISTS idx_secret_message_receiver ON secret_message(receiver_id)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_user ON security_alert(user_id)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_timestamp ON security_alert(timestamp)@@


-- 4. WIDOKI
CREATE OR REPLACE VIEW v_active_security_alerts AS
SELECT
    sa.id,
    u.username,
    sa.description,
    sa.severity_level,
    sa.timestamp
FROM security_alert sa
         JOIN app_user u ON sa.user_id = u.id
WHERE sa.severity_level = 'HIGH'
  AND sa.timestamp >= NOW() - INTERVAL '24 hours'@@


-- 5. FUNKCJE
CREATE OR REPLACE FUNCTION fn_count_recent_alerts(target_user_id BIGINT, minutes_interval INT)
RETURNS INT AS $$
DECLARE
alert_count INT;
BEGIN
SELECT COUNT(*) INTO alert_count
FROM security_alert
WHERE user_id = target_user_id
  AND severity_level = 'HIGH'
  AND timestamp >= NOW() - (minutes_interval || ' minutes')::INTERVAL;

RETURN alert_count;
END;
$$ LANGUAGE plpgsql@@
SET search_path TO workshop;
    
-- ============================================================
-- ANALIZA BEZPIECZEŃSTWA SCHEMATU
-- ============================================================
-- app_user.password_hash          → BCrypt, bezpieczny
-- app_user.public_key             → klucz publiczny RSA — może być JAWNY (to jego cel)
-- app_user.signing_public_key     → klucz publiczny Ed25519 — może być JAWNY
-- app_user.encrypted_private_key  → klucz prywatny RSA zaszyfrowany PBKDF2+AES-256
--                                   bez hasła E2EE użytkownika = bezużyteczne dane
-- app_user.encrypted_signing_priv_key → klucz prywatny Ed25519 zaszyfrowany PBKDF2+AES-256
--                                       bez hasła E2EE = bezużyteczne dane
-- app_user.kdf_salt               → sól PBKDF2, jawna zgodnie ze standardem NIST
--                                   tajność soli NIE jest wymagana — siłę zapewniają iteracje
-- secret_message.encrypted_content → zaszyfrowana treść (AES lub RSA)
-- secret_message.secret_iv        → IV dla AES-CBC, może być JAWNY (standardowa praktyka)
-- secret_message.digital_signature → podpis Ed25519, może być JAWNY (służy weryfikacji)
-- ============================================================
-- WNIOSEK: schemat nie zawiera żadnych danych wrażliwych w postaci jawnej.
-- Jedynym punktem krytycznym jest hasło E2EE użytkownika — nigdy nie trafia do bazy.
-- ============================================================


-- ============================================================
-- 1. SEKWENCJE
-- ============================================================
CREATE SEQUENCE IF NOT EXISTS user_seq             START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS user_session_seq     START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS message_category_seq START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS message_seq          START WITH 1 INCREMENT BY 1@@
CREATE SEQUENCE IF NOT EXISTS alert_seq            START WITH 1 INCREMENT BY 1@@


-- ============================================================
-- 2. TABELE
-- ============================================================

-- Użytkownicy systemu
-- Kolumny kryptograficzne obsługują dwa tryby:
--   STANDARD           → używane tylko: id, username, password_hash
--   END_TO_END_ENCRYPTED → używane też: public_key, signing_public_key,
--                          encrypted_private_key, encrypted_signing_priv_key, kdf_salt
CREATE TABLE IF NOT EXISTS app_user (
    id                          BIGINT       NOT NULL DEFAULT nextval('user_seq'),
    username                    VARCHAR(255) NOT NULL UNIQUE,
    password_hash               VARCHAR(255) NOT NULL,

    -- E2EE: klucze publiczne (jawne — do pobrania przez nadawców)
    public_key                  TEXT         DEFAULT NULL,
    signing_public_key          TEXT         DEFAULT NULL,

    -- E2EE: klucze prywatne zaszyfrowane hasłem E2EE przez PBKDF2+AES-256
    -- Przechowywanie w bazie jest bezpieczne — bez hasła E2EE są bezużyteczne
    encrypted_private_key       TEXT         DEFAULT NULL,
    encrypted_signing_priv_key  TEXT         DEFAULT NULL,

    -- Sól PBKDF2 — jawna zgodnie ze standardem (NIST SP 800-132)
    kdf_salt                    VARCHAR(64)  DEFAULT NULL,

    PRIMARY KEY (id)
)@@


-- Sesje użytkowników (do przyszłej rozbudowy audytu)
CREATE TABLE IF NOT EXISTS user_session (
    id            BIGINT       NOT NULL DEFAULT nextval('user_session_seq'),
    user_id       BIGINT       NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    login_time    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active     BOOLEAN      DEFAULT TRUE,
    PRIMARY KEY (id),
    CONSTRAINT fk_user_session_user
        FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
)@@


-- Kategorie wiadomości
CREATE TABLE IF NOT EXISTS message_category (
    id            BIGINT      NOT NULL DEFAULT nextval('message_category_seq'),
    category_name VARCHAR(50) NOT NULL UNIQUE,
    PRIMARY KEY (id)
)@@

-- Dwie aktywne kategorie:
--   STANDARD            szyfrowanie symetryczne AES-256-CBC, hasło znane obu stronom
--   END_TO_END_ENCRYPTED  RSA-2048 + Ed25519 + PBKDF2, serwer nie może odszyfrować
INSERT INTO message_category (category_name)
VALUES ('STANDARD'), ('END_TO_END_ENCRYPTED')
ON CONFLICT (category_name) DO NOTHING@@


-- Wiadomości (zaszyfrowane)
CREATE TABLE IF NOT EXISTS secret_message (
    id                BIGINT    NOT NULL DEFAULT nextval('message_seq'),
    sender_id         BIGINT    NOT NULL,
    receiver_id       BIGINT    NOT NULL,
    category_id       BIGINT    NOT NULL,

    -- Zaszyfrowana treść: Base64(AES) lub Base64(RSA-OAEP)
    encrypted_content TEXT      NOT NULL,

    -- IV dla trybu AES-CBC (jawny — standardowa praktyka kryptograficzna)
    -- Wartość 'E2EE_NO_IV' gdy kategoria = END_TO_END_ENCRYPTED
    secret_iv         VARCHAR(64) NOT NULL DEFAULT 'MIGRATED_NO_IV',

    -- Losowa sól PBKDF2 per wiadomość (jawna — standardowa praktyka)
    -- Wartość 'E2EE_NO_SALT' gdy kategoria = END_TO_END_ENCRYPTED
    -- Wartość 'MIGRATED_NO_SALT' dla wiadomości sprzed migracji
    secret_salt       VARCHAR(64) NOT NULL DEFAULT 'MIGRATED_NO_SALT',

    -- Podpis cyfrowy Ed25519 zaszyfrowanej treści (jawny — służy weryfikacji)
    -- NULL dla wiadomości STANDARD
    digital_signature TEXT      DEFAULT NULL,

    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_message_sender
        FOREIGN KEY (sender_id)   REFERENCES app_user(id)        ON DELETE CASCADE,
    CONSTRAINT fk_message_receiver
        FOREIGN KEY (receiver_id) REFERENCES app_user(id)        ON DELETE CASCADE,
    CONSTRAINT fk_message_category
        FOREIGN KEY (category_id) REFERENCES message_category(id)
)@@


-- ============================================================
-- 3. INDEKSY
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_user_username            ON app_user(username)@@
CREATE INDEX IF NOT EXISTS idx_user_session_user        ON user_session(user_id)@@
CREATE INDEX IF NOT EXISTS idx_secret_message_sender    ON secret_message(sender_id)@@
CREATE INDEX IF NOT EXISTS idx_secret_message_receiver  ON secret_message(receiver_id)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_user      ON security_alert(user_id)@@
CREATE INDEX IF NOT EXISTS idx_security_alert_timestamp ON security_alert(timestamp)@@


-- ============================================================
-- 4. WIDOKI
-- ============================================================

-- Aktywne alerty HIGH z ostatnich 24h (do monitoringu)
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


-- ============================================================
-- 5. FUNKCJE
-- ============================================================

-- Zlicza alerty HIGH dla użytkownika z ostatnich N minut
-- Używane do dynamicznej oceny ryzyka logowania/wysyłki
    CREATE OR REPLACE FUNCTION fn_count_recent_alerts(target_user_id BIGINT, minutes_interval INT)
    RETURNS INT AS $$
DECLARE
alert_count INT;
BEGIN
SELECT COUNT(*) INTO alert_count
FROM security_alert
WHERE user_id       = target_user_id
  AND severity_level = 'HIGH'
  AND timestamp      >= NOW() - (minutes_interval || ' minutes')::INTERVAL;
RETURN alert_count;
END;
$$ LANGUAGE plpgsql@@
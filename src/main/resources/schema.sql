SET search_path TO workshop;

-- ============================================================
-- ANALIZA BEZPIECZEŃSTWA SCHEMATU
-- ============================================================
-- app_user.password_hash               → BCrypt, bezpieczny
-- app_user.public_key                  → klucz publiczny RSA — może być JAWNY (to jego cel)
-- app_user.signing_public_key          → klucz publiczny Ed25519 — może być JAWNY
-- app_user.encrypted_private_key       → klucz prywatny RSA zaszyfrowany PBKDF2+AES-256
--                                        bez hasła E2EE użytkownika = bezużyteczne dane
-- app_user.encrypted_signing_priv_key  → klucz prywatny Ed25519 zaszyfrowany PBKDF2+AES-256
--                                        bez hasła E2EE = bezużyteczne dane
-- app_user.kdf_salt                    → sól PBKDF2, jawna zgodnie ze standardem NIST
--                                        tajność soli NIE jest wymagana — siłę zapewniają iteracje
-- app_user.account_status              → ACTIVE / BLOCKED / SUSPENDED
-- app_user.blocked_until               → czas końca blokady (domyślnie +24h)
-- app_user.block_reason                → powód blokady (z Drools)
-- secret_message.encrypted_content     → zaszyfrowana treść (AES lub RSA)
-- secret_message.secret_iv             → IV dla AES-GCM, może być JAWNY (standardowa praktyka)
-- secret_message.digital_signature     → podpis Ed25519, może być JAWNY (służy weryfikacji)
-- ============================================================
-- WNIOSEK: schemat nie zawiera żadnych danych wrażliwych w postaci jawnej.
-- Jedynym punktem krytycznym jest hasło E2EE użytkownika — nigdy nie trafia do bazy.
-- ============================================================


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

-- --------------------------------------------------------
-- Kategorie alertów bezpieczeństwa (3 poziomy: LOW, MEDIUM, HIGH)
-- Osobna tabela dla spójności typów i łatwości rozbudowy
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_severity (
    id            BIGINT      NOT NULL DEFAULT nextval('alert_category_seq'),
    severity_code VARCHAR(10) NOT NULL UNIQUE,   -- LOW | MEDIUM | HIGH
    severity_rank INT         NOT NULL UNIQUE,   -- 1=LOW, 2=MEDIUM, 3=HIGH (do porównań)
    description   VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
)@@

INSERT INTO alert_severity (severity_code, severity_rank, description)
VALUES
    ('LOW',    1, 'Zdarzenie niskiego ryzyka — monitorowane, nie wymaga natychmiastowej akcji'),
    ('MEDIUM', 2, 'Zdarzenie średniego ryzyka — wiadomość zablokowana lub podejrzane zachowanie'),
    ('HIGH',   3, 'Zdarzenie krytyczne — konto zablokowane, sesje unieważnione')
ON CONFLICT (severity_code) DO NOTHING@@


-- --------------------------------------------------------
-- Użytkownicy systemu
-- Kolumny kryptograficzne obsługują dwa tryby:
--   STANDARD             → używane tylko: id, username, password_hash
--   END_TO_END_ENCRYPTED → używane też: public_key, signing_public_key,
--                          encrypted_private_key, encrypted_signing_priv_key, kdf_salt
--
-- Nowe kolumny bezpieczeństwa (Drools):
--   account_status  → ACTIVE (domyślny), BLOCKED, SUSPENDED
--   blocked_until   → timestamp końca blokady; NULL gdy konto aktywne
--   block_reason    → tekst opisujący powód blokady (generowany przez Drools)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_user (
    id                          BIGINT        NOT NULL DEFAULT nextval('user_seq'),
    username                    VARCHAR(255)  NOT NULL UNIQUE,
    password_hash               VARCHAR(255)  NOT NULL,

    -- E2EE: klucze publiczne (jawne — do pobrania przez nadawców)
    public_key                  TEXT          DEFAULT NULL,
    signing_public_key          TEXT          DEFAULT NULL,

    -- E2EE: klucze prywatne zaszyfrowane hasłem E2EE przez PBKDF2+AES-256
    -- Przechowywanie w bazie jest bezpieczne — bez hasła E2EE są bezużyteczne
    encrypted_private_key       TEXT          DEFAULT NULL,
    encrypted_signing_priv_key  TEXT          DEFAULT NULL,

    -- Sól PBKDF2 — jawna zgodnie ze standardem (NIST SP 800-132)
    kdf_salt                    VARCHAR(64)   DEFAULT NULL,

    -- ---- NOWE: status bezpieczeństwa konta (zarządzane przez Drools) ----
    -- Dopuszczalne wartości: ACTIVE, BLOCKED, SUSPENDED
    account_status              VARCHAR(20)   NOT NULL DEFAULT 'ACTIVE',

    -- Czas do kiedy konto jest zablokowane (NULL = aktywne lub bezterminowe)
    -- Domyślna blokada = +24h od momentu zdarzenia (ustawiane przez DroolsSecurityService)
    blocked_until               TIMESTAMP     DEFAULT NULL,

    -- Czytelny powód blokady generowany przez silnik reguł
    block_reason                TEXT          DEFAULT NULL,

    PRIMARY KEY (id),
    CONSTRAINT chk_account_status CHECK (account_status IN ('ACTIVE', 'BLOCKED', 'SUSPENDED'))
)@@


-- --------------------------------------------------------
-- Sesje użytkowników
--
-- Rola zmieniona: tabela używana przez DroolsSecurityService
-- do unieważniania aktywnych sesji przy blokadzie konta (HIGH alert).
-- Spring Security zarządza sesjami — tutaj przechowujemy
-- identyfikatory sesji Spring (HttpSession.getId()) w celu
-- ich przymusowego unieważnienia przez SessionRegistry.
--
-- Cykl życia wpisu:
--   LOGIN  → INSERT z is_active=TRUE, logout_time=NULL
--   LOGOUT → UPDATE is_active=FALSE, logout_time=NOW()
--   BLOCK  → UPDATE is_active=FALSE, logout_time=NOW(),
--             invalidation_reason='SECURITY_BLOCK' dla wszystkich aktywnych sesji
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_session (
    id                  BIGINT        NOT NULL DEFAULT nextval('user_session_seq'),
    user_id             BIGINT        NOT NULL,

    -- Identyfikator sesji Spring Security (HttpSession.getId())
    -- Używany do unieważnienia konkretnej sesji przez SessionRegistry
    session_token       VARCHAR(255)  NOT NULL UNIQUE,

    -- Dodatkowe metadane audytowe
    login_time          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time         TIMESTAMP     DEFAULT NULL,
    ip_address          VARCHAR(45)   DEFAULT NULL,   -- IPv4 lub IPv6
    user_agent          VARCHAR(512)  DEFAULT NULL,   -- nagłówek User-Agent przeglądarki

    is_active           BOOLEAN       NOT NULL DEFAULT TRUE,

    -- Powód unieważnienia sesji (NULL = normalne wylogowanie)
    -- Wypełniany przez Drools przy HIGH alert: 'SECURITY_BLOCK_BRUTE_FORCE' itp.
    invalidation_reason VARCHAR(100)  DEFAULT NULL,

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
--   STANDARD             → szyfrowanie symetryczne AES-256-GCM, hasło znane obu stronom
--                          Drools MOŻE skanować treść (DLP)
--   END_TO_END_ENCRYPTED → RSA-2048 + Ed25519 + PBKDF2, serwer nie może odszyfrować
--                          Drools NIE MA PRAWA skanować treści
INSERT INTO message_category (category_name)
VALUES ('STANDARD'), ('END_TO_END_ENCRYPTED')
ON CONFLICT (category_name) DO NOTHING@@


-- Wiadomości (zaszyfrowane)
CREATE TABLE IF NOT EXISTS secret_message (
    id                BIGINT      NOT NULL DEFAULT nextval('message_seq'),
    sender_id         BIGINT      NOT NULL,
    receiver_id       BIGINT      NOT NULL,
    category_id       BIGINT      NOT NULL,

    -- Zaszyfrowana treść: Base64(AES-GCM) lub Base64(RSA-OAEP)
    encrypted_content TEXT        NOT NULL,

    -- IV dla trybu AES-GCM (jawny — standardowa praktyka kryptograficzna)
    -- Wartość 'E2EE_NO_IV' gdy kategoria = END_TO_END_ENCRYPTED
    secret_iv         VARCHAR(64) NOT NULL DEFAULT 'MIGRATED_NO_IV',

    -- Losowa sól PBKDF2 per wiadomość (jawna — standardowa praktyka)
    -- Wartość 'E2EE_NO_SALT' gdy kategoria = END_TO_END_ENCRYPTED
    -- Wartość 'MIGRATED_NO_SALT' dla wiadomości sprzed migracji
    secret_salt       VARCHAR(64) NOT NULL DEFAULT 'MIGRATED_NO_SALT',

    -- Podpis cyfrowy Ed25519 zaszyfrowanej treści (jawny — służy weryfikacji)
    -- NULL dla wiadomości STANDARD
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


-- --------------------------------------------------------
-- Alerty bezpieczeństwa (generowane przez Drools)
--
-- severity_level odwołuje się do tabeli alert_severity (kolumna severity_code).
-- Nie jest FK aby uniknąć narzutu JOIN przy masowych insertach z Drools —
-- spójność zapewnia CHECK constraint i logika serwisu.
-- alert_type — stały katalog typów zdarzeń (patrz CHECK poniżej)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_alert (
    id              BIGINT        NOT NULL DEFAULT nextval('alert_seq'),
    user_id         BIGINT        NOT NULL,

    -- Poziom ważności: LOW | MEDIUM | HIGH (spójny z tabelą alert_severity)
    severity_level  VARCHAR(10)   NOT NULL,

    -- Typ zdarzenia — katalog zamknięty, zmiana wymaga migracji
    alert_type      VARCHAR(50)   NOT NULL,

    -- Czytelny opis zdarzenia (generowany przez regułę Drools)
    description     TEXT          NOT NULL,

    -- Czas wystąpienia zdarzenia
    timestamp       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_alert_user
        FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    CONSTRAINT chk_severity_level
        CHECK (severity_level IN ('LOW', 'MEDIUM', 'HIGH')),
    CONSTRAINT chk_alert_type
        CHECK (alert_type IN (
            -- Logowanie
            'BRUTE_FORCE',             -- >5 błędnych logowań w 3 min → HIGH
            'LOGIN_AFTER_HOURS_LOW',   -- logowanie 17–24 → LOW
            'LOGIN_AFTER_HOURS_HIGH',  -- logowanie 0–7   → HIGH (nikt nie powinien być w biurze)
            -- DLP (wiadomości STANDARD)
            'DLP_SENSITIVE_KEYWORD',   -- słowo kluczowe: pesel, hasło, karta kredytowa, pin
            'DLP_PESEL_PATTERN',       -- dokładnie 11 cyfr
            'DLP_CARD_PATTERN',        -- dokładnie 16 cyfr
            'DLP_LINK_DETECTED',       -- link w treści wiadomości
            -- Eskalacja
            'ESCALATION_AGGREGATED'    -- agregacja LOW/MEDIUM → AUTO HIGH + blokada
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

-- Oryginalna funkcja HIGH-only (zachowana dla zgodności wstecznej)
CREATE OR REPLACE FUNCTION fn_count_recent_alerts(
    target_user_id   BIGINT,
    minutes_interval INT
)
RETURNS INT AS $$
BEGIN
RETURN fn_count_recent_alerts_by_level(target_user_id, minutes_interval, 'HIGH');
END;
$$ LANGUAGE plpgsql@@

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
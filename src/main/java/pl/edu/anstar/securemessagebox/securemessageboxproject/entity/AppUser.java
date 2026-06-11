package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Encja użytkownika systemu SecureMessageBox.
 *
 * Nowe kolumny bezpieczeństwa (zarządzane przez DroolsSecurityService):
 *   - accountStatus  → ACTIVE (domyślny), BLOCKED, SUSPENDED
 *   - blockedUntil   → czas końca blokady (domyślnie +24h); NULL = konto aktywne
 *   - blockReason    → czytelny powód blokady generowany przez silnik reguł Drools
 */
@Entity
@Table(name = "app_user")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq_gen")
    @SequenceGenerator(name = "user_seq_gen", sequenceName = "user_seq", allocationSize = 1)
    private Long id;

    @Column(unique = true, nullable = false, length = 255)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    // ---- Klucze kryptograficzne E2EE ----

    /** Klucz publiczny RSA — każdy może pobrać, by zaszyfrować wiadomość E2EE */
    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    /** Klucz prywatny RSA zaszyfrowany PBKDF2+AES-256-GCM (hasłem E2EE użytkownika) */
    @Column(name = "encrypted_private_key", columnDefinition = "TEXT")
    private String encryptedPrivateKey;

    /** Klucz prywatny Ed25519 zaszyfrowany PBKDF2+AES-256-GCM (tym samym hasłem E2EE) */
    @Column(name = "encrypted_signing_priv_key", columnDefinition = "TEXT")
    private String encryptedSigningPrivateKey;

    /** Klucz publiczny Ed25519 — do weryfikacji podpisów wiadomości tego użytkownika */
    @Column(name = "signing_public_key", columnDefinition = "TEXT")
    private String signingPublicKey;

    /** Sól PBKDF2 — potrzebna do wyprowadzenia klucza AES z hasła E2EE */
    @Column(name = "kdf_salt", length = 64)
    private String kdfSalt;

    // ---- Nowe: status konta (zarządzany przez Drools) ----

    /**
     * Status konta użytkownika.
     * Dopuszczalne wartości: ACTIVE, BLOCKED, SUSPENDED
     *
     * ACTIVE    → normalna praca
     * BLOCKED   → zablokowane przez Drools (brute-force, nocne logowanie, eskalacja alertów)
     *             Blokada trwa domyślnie 24h (do pola blockedUntil).
     *             Użytkownik NIE może się zalogować ani ODBIERAĆ wiadomości.
     * SUSPENDED → manualna blokada przez admina (bez daty wygaśnięcia)
     */
    @Column(name = "account_status", nullable = false, length = 20)
    private String accountStatus = "ACTIVE";

    /**
     * Czas wygaśnięcia blokady.
     * NULL gdy konto ma status ACTIVE lub SUSPENDED (bezterminowe).
     * Drools ustawia to pole na NOW() + 24h przy każdej automatycznej blokadzie.
     * Funkcja fn_unblock_expired_accounts() (lub scheduler Spring) czyści
     * blokady po upływie tego czasu.
     */
    @Column(name = "blocked_until")
    private LocalDateTime blockedUntil;

    /**
     * Czytelny powód blokady konta — generowany przez regułę Drools.
     * Przykłady:
     *   "BRUTE_FORCE: 6 nieudanych logowań w 3 minuty (2025-06-01 03:14)"
     *   "LOGIN_AFTER_HOURS_HIGH: próba logowania o 03:14 — poza dopuszczonymi godzinami"
     *   "ESCALATION: 5 alertów LOW w 10 min — automatyczna eskalacja do HIGH"
     */
    @Column(name = "block_reason", columnDefinition = "TEXT")
    private String blockReason;

    // ---- Relacje ----

    @OneToMany(mappedBy = "sender", fetch = FetchType.LAZY)
    private List<SecretMessage> sentMessages;

    @OneToMany(mappedBy = "receiver", fetch = FetchType.LAZY)
    private List<SecretMessage> receivedMessages;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<SecurityAlert> alerts;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<UserSession> sessions;

    // ---- Metody pomocnicze ----

    /** Zwraca true jeśli konto jest aktualnie zablokowane (uwzględnia czas wygaśnięcia). */
    @Transient
    public boolean isCurrentlyBlocked() {
        if (!"BLOCKED".equals(accountStatus) && !"SUSPENDED".equals(accountStatus)) {
            return false;
        }
        // Blokada BLOCKED z terminem — sprawdź czy jeszcze trwa
        if ("BLOCKED".equals(accountStatus) && blockedUntil != null) {
            return LocalDateTime.now().isBefore(blockedUntil);
        }
        // BLOCKED bez terminu lub SUSPENDED — zablokowany bezterminowo
        return true;
    }
}
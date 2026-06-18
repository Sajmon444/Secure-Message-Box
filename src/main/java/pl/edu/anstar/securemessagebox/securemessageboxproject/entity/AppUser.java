package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Encja użytkownika systemu SecureMessageBox.
 * Przechowuje dane uwierzytelniające, klucze kryptograficzne E2EE oraz status bezpieczeństwa konta,
 * zarządzany automatycznie przez silnik reguł Drools.
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

    /** Klucz publiczny RSA (udostępniany publicznie). */
    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    /** Klucz prywatny RSA (zaszyfrowany algorytmem AES-256-GCM). */
    @Column(name = "encrypted_private_key", columnDefinition = "TEXT")
    private String encryptedPrivateKey;

    /** Klucz prywatny Ed25519 (zaszyfrowany algorytmem AES-256-GCM). */
    @Column(name = "encrypted_signing_priv_key", columnDefinition = "TEXT")
    private String encryptedSigningPrivateKey;

    /** Klucz publiczny Ed25519 do weryfikacji podpisów użytkownika. */
    @Column(name = "signing_public_key", columnDefinition = "TEXT")
    private String signingPublicKey;

    /** Sól PBKDF2 używana przy wyprowadzaniu klucza AES. */
    @Column(name = "kdf_salt", length = 64)
    private String kdfSalt;

    // ---- Zarządzanie statusem konta (Drools) ----

    /** * Status konta użytkownika (ACTIVE, BLOCKED, SUSPENDED).
     */
    @Column(name = "account_status", nullable = false, length = 20)
    private String accountStatus = "ACTIVE";

    /** * Data wygaśnięcia blokady (dla statusu BLOCKED).
     * Wartość NULL oznacza brak ograniczenia czasowego.
     */
    @Column(name = "blocked_until")
    private LocalDateTime blockedUntil;

    /** Opisowy powód blokady wygenerowany przez system. */
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

    /**
     * Weryfikuje, czy konto jest aktualnie zablokowane.
     * Uwzględnia zarówno status konta, jak i termin wygaśnięcia blokady.
     */
    @Transient
    public boolean isCurrentlyBlocked() {
        if (!"BLOCKED".equals(accountStatus) && !"SUSPENDED".equals(accountStatus)) {
            return false;
        }
        if ("BLOCKED".equals(accountStatus) && blockedUntil != null) {
            return LocalDateTime.now().isBefore(blockedUntil);
        }
        return true;
    }
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

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

    // Klucz publiczny RSA — każdy może pobrać, by zaszyfrować wiadomość
    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    // Klucz prywatny RSA zaszyfrowany PBKDF2+AES (hasłem E2EE użytkownika)
    @Column(name = "encrypted_private_key", columnDefinition = "TEXT")
    private String encryptedPrivateKey;

    // Klucz prywatny Ed25519 zaszyfrowany PBKDF2+AES (tym samym hasłem E2EE)
    // Przechowywany w bazie — nigdy nie ujawniany w formie jawnej
    @Column(name = "encrypted_signing_priv_key", columnDefinition = "TEXT")
    private String encryptedSigningPrivateKey;

    // Klucz publiczny Ed25519 — do weryfikacji podpisów wiadomości tego użytkownika
    @Column(name = "signing_public_key", columnDefinition = "TEXT")
    private String signingPublicKey;

    // Sól PBKDF2 — potrzebna do wyprowadzenia klucza AES z hasła E2EE
    @Column(name = "kdf_salt", length = 64)
    private String kdfSalt;

    @OneToMany(mappedBy = "sender", fetch = FetchType.LAZY)
    private List<SecretMessage> sentMessages;

    @OneToMany(mappedBy = "receiver", fetch = FetchType.LAZY)
    private List<SecretMessage> receivedMessages;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<SecurityAlert> alerts;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<UserSession> sessions;
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;

/**
 * Encja reprezentująca zaszyfrowaną wiadomość w systemie.
 * Przechowuje zarówno wiadomości typu STANDARD, jak i END_TO_END_ENCRYPTED,
 * wraz z niezbędnymi metadanymi kryptograficznymi.
 */
@Entity
@Table(name = "secret_message")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecretMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "message_seq_gen")
    @SequenceGenerator(name = "message_seq_gen", sequenceName = "message_seq", allocationSize = 1)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "sender_id", nullable = false, foreignKey = @ForeignKey(name = "fk_message_sender"))
    private AppUser sender;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "receiver_id", nullable = false, foreignKey = @ForeignKey(name = "fk_message_receiver"))
    private AppUser receiver;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", nullable = false, foreignKey = @ForeignKey(name = "fk_message_category"))
    private MessageCategory category;

    /** Zaszyfrowana treść wiadomości. */
    @Column(name = "encrypted_content", nullable = false, columnDefinition = "TEXT")
    private String encryptedContent;

    /** Wektor inicjalizacyjny AES (dla STANDARD) lub flaga "E2EE_NO_IV" (dla E2EE). */
    @Column(name = "secret_iv", nullable = false, length = 64)
    private String secretIv;

    /**
     * Sól PBKDF2 dla wiadomości STANDARD lub flaga "E2EE_NO_SALT" dla E2EE.
     * Sól jest jawna, zapewniając unikalność kluczy dla algorytmu PBKDF2.
     */
    @Column(name = "secret_salt", nullable = false, length = 64)
    private String secretSalt;

    /** Podpis cyfrowy Ed25519 (tylko dla kategorii END_TO_END_ENCRYPTED). */
    @Column(name = "digital_signature", columnDefinition = "TEXT")
    private String digitalSignature;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
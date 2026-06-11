package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Alert bezpieczeństwa generowany przez silnik reguł Drools.
 *
 * Poziomy ważności (severity_level) są spójne z tabelą alert_severity:
 *   LOW    → zdarzenie monitorowane, brak natychmiastowej akcji
 *   MEDIUM → wiadomość zablokowana lub podejrzane zachowanie
 *   HIGH   → konto zablokowane, wszystkie sesje unieważnione
 *
 * Typy alertów (alert_type) — zamknięty katalog zgodny z CHECK w SQL:
 *   Logowanie:
 *     BRUTE_FORCE             → >5 błędnych prób logowania w 3 min
 *     LOGIN_AFTER_HOURS_LOW   → logowanie w godzinach 17:00–00:00
 *     LOGIN_AFTER_HOURS_HIGH  → logowanie w godzinach 00:00–07:00
 *   DLP (tylko wiadomości STANDARD / AES):
 *     DLP_SENSITIVE_KEYWORD   → słowo kluczowe: pesel, hasło, karta kredytowa, pin
 *     DLP_PESEL_PATTERN       → ciąg dokładnie 11 cyfr
 *     DLP_CARD_PATTERN        → ciąg dokładnie 16 cyfr
 *     DLP_LINK_DETECTED       → link (http/https/www) w treści
 *   Eskalacja:
 *     ESCALATION_AGGREGATED   → agregacja LOW/MEDIUM → automatyczny HIGH + blokada
 */
@Entity
@Table(name = "security_alert")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "alert_seq_gen")
    @SequenceGenerator(name = "alert_seq_gen", sequenceName = "alert_seq", allocationSize = 1)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_alert_user"))
    private AppUser user;

    /**
     * Poziom ważności: LOW | MEDIUM | HIGH
     * Spójny z tabelą alert_severity (severity_code).
     */
    @Column(name = "severity_level", nullable = false, length = 10)
    private String severityLevel;

    /**
     * Typ zdarzenia — stały katalog, musi być jedną z wartości zdefiniowanych
     * w CHECK constraint tabeli security_alert.
     * Używany przez Drools do eskalacji (liczymy po typach).
     */
    @Column(name = "alert_type", nullable = false, length = 50)
    private String alertType;

    /** Czytelny opis zdarzenia (generowany przez regułę Drools) */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @CreationTimestamp
    @Column(name = "timestamp", nullable = false, updatable = false)
    private LocalDateTime timestamp;
}
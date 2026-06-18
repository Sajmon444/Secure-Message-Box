package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Encja reprezentująca alert bezpieczeństwa wygenerowany przez silnik reguł Drools.
 * Przechowuje informacje o incydentach, ich dotkliwości oraz typie, umożliwiając
 * audyt i automatyczną reakcję systemu na zagrożenia.
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
     * Poziom ważności alertu (LOW, MEDIUM, HIGH).
     * Określa stopień zagrożenia i wymaganą reakcję systemu.
     */
    @Column(name = "severity_level", nullable = false, length = 10)
    private String severityLevel;

    /**
     * Typ zdarzenia, ściśle powiązany z ograniczeniami bazy danych (CHECK constraint).
     * Wykorzystywany przez reguły Drools do identyfikacji i eskalacji zagrożeń.
     */
    @Column(name = "alert_type", nullable = false, length = 50)
    private String alertType;

    /** Szczegółowy opis incydentu wygenerowany przez silnik reguł. */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @CreationTimestamp
    @Column(name = "timestamp", nullable = false, updatable = false)
    private LocalDateTime timestamp;
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Tabela słownikowa poziomów ważności alertów bezpieczeństwa.
 *
 * Zawiera trzy stałe rekordy (ładowane przez schema.sql):
 *   LOW    (rank=1) → zdarzenie monitorowane
 *   MEDIUM (rank=2) → wiadomość zablokowana
 *   HIGH   (rank=3) → konto zablokowane + sesje unieważnione
 *
 * Kolumna severity_rank umożliwia porównania (>,<,>=) między poziomami
 * bez hard-kodowania stringów w logice biznesowej.
 */
@Entity
@Table(name = "alert_severity")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AlertSeverity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "alert_category_seq_gen")
    @SequenceGenerator(name = "alert_category_seq_gen", sequenceName = "alert_category_seq", allocationSize = 1)
    private Long id;

    /** Kod poziomu: LOW | MEDIUM | HIGH */
    @Column(name = "severity_code", unique = true, nullable = false, length = 10)
    private String severityCode;

    /** Ranga numeryczna do porównań: 1=LOW, 2=MEDIUM, 3=HIGH */
    @Column(name = "severity_rank", unique = true, nullable = false)
    private Integer severityRank;

    @Column(nullable = false, length = 255)
    private String description;

    // Stałe dla kodu aplikacji — unikamy magic stringów
    public static final String LOW    = "LOW";
    public static final String MEDIUM = "MEDIUM";
    public static final String HIGH   = "HIGH";
}

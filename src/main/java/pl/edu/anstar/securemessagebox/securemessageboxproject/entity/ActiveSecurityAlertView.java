package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Immutable;
import java.time.LocalDateTime;

/**
 * Encja odwzorowująca widok bazodanowy (v_active_security_alerts).
 * Służy wyłącznie do odczytu danych o aktywnych alertach bezpieczeństwa.
 * Adnotacja @Immutable zapewnia, że encja ta nie podlega modyfikacjom w ramach sesji Hibernate.
 */
@Entity
@Table(name = "v_active_security_alerts")
@Immutable
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ActiveSecurityAlertView {

    @Id
    private Long id;

    /** Nazwa użytkownika, którego dotyczy alert. */
    private String username;

    /** Szczegółowy opis incydentu bezpieczeństwa. */
    private String description;

    /** Poziom istotności (np. HIGH, MEDIUM). */
    private String severityLevel;

    /** Czas wystąpienia zdarzenia. */
    private LocalDateTime timestamp;
}
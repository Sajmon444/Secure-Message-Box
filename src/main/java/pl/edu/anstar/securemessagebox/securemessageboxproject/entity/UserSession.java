package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Encja reprezentująca sesję użytkownika, wykorzystywana do celów audytowych
 * oraz zarządzania bezpieczeństwem poprzez wymuszone unieważnianie sesji (integracja z Drools).
 */
@Entity
@Table(name = "user_session")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_session_seq_gen")
    @SequenceGenerator(name = "user_session_seq_gen", sequenceName = "user_session_seq", allocationSize = 1)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_user_session_user"))
    private AppUser user;

    /**
     * Identyfikator sesji Spring Security (HttpSession.getId()).
     * Umożliwia lokalizację i unieważnienie sesji w SessionRegistry.
     */
    @Column(name = "session_token", unique = true, nullable = false, length = 255)
    private String sessionToken;

    @CreationTimestamp
    @Column(name = "login_time", nullable = false, updatable = false)
    private LocalDateTime loginTime;

    /** Czas zakończenia sesji. Wartość NULL oznacza, że sesja pozostaje aktywna. */
    @Column(name = "logout_time")
    private LocalDateTime logoutTime;

    /** Adres IP użytkownika (obsługuje IPv4 oraz IPv6). */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /** Informacje o przeglądarce użytkownika (User-Agent). */
    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    /** * Powód unieważnienia sesji (np. zablokowanie przez reguły Drools).
     * Wartość NULL oznacza poprawne wylogowanie przez użytkownika.
     */
    @Column(name = "invalidation_reason", length = 100)
    private String invalidationReason;
}
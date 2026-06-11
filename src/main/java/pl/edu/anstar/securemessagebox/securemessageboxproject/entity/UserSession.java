package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Sesja użytkownika — audyt i unieważnianie sesji przez Drools.
 *
 * Rola tabeli:
 *   Przechowuje identyfikatory sesji Spring Security (HttpSession.getId()),
 *   dzięki czemu DroolsSecurityService może wymusić natychmiastowe wylogowanie
 *   użytkownika przez unieważnienie wszystkich jego aktywnych sesji w SessionRegistry.
 *
 * Cykl życia rekordu:
 *   LOGIN  → INSERT: is_active=TRUE, logout_time=NULL, invalidation_reason=NULL
 *   LOGOUT → UPDATE: is_active=FALSE, logout_time=NOW(), invalidation_reason=NULL
 *   BLOCK  → UPDATE: is_active=FALSE, logout_time=NOW(),
 *             invalidation_reason=<kod z Drools> dla WSZYSTKICH aktywnych sesji użytkownika
 *
 * Integracja ze Spring Security:
 *   SessionRegistryIntegrationService.recordLogin()  → INSERT
 *   SessionRegistryIntegrationService.recordLogout() → UPDATE
 *   DroolsSecurityService.invalidateAllSessions()    → UPDATE + wywołanie
 *                                                       SessionRegistry.removeSessionInformation()
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
     * Identyfikator sesji Spring Security: HttpSession.getId()
     * Używany do lokalizacji sesji w SessionRegistry i jej unieważnienia.
     */
    @Column(name = "session_token", unique = true, nullable = false, length = 255)
    private String sessionToken;

    @CreationTimestamp
    @Column(name = "login_time", nullable = false, updatable = false)
    private LocalDateTime loginTime;

    /** Czas wylogowania (normalnego lub wymuszonego przez Drools). NULL = sesja aktywna. */
    @Column(name = "logout_time")
    private LocalDateTime logoutTime;

    /** Adres IP z którego nastąpiło logowanie (IPv4 lub IPv6, max 45 znaków). */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /** Nagłówek User-Agent przeglądarki — do celów audytowych. */
    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    /**
     * Powód unieważnienia sesji — wypełniany przez Drools przy HIGH alert.
     * NULL = normalne wylogowanie przez użytkownika.
     * Przykładowe wartości:
     *   'SECURITY_BLOCK_BRUTE_FORCE'
     *   'SECURITY_BLOCK_NIGHT_LOGIN'
     *   'SECURITY_BLOCK_ESCALATION'
     */
    @Column(name = "invalidation_reason", length = 100)
    private String invalidationReason;
}
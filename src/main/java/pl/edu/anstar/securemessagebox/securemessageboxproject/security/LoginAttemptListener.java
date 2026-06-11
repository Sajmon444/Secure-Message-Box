package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.service.DroolsSecurityService;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.UserSession;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.SecurityAlertRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.UserSessionRepository;

import java.time.LocalDateTime;

/**
 * Listener zdarzeń Spring Security — most między Spring a Drools.
 *
 * Nasłuchuje na:
 *   AuthenticationSuccessEvent    → udane logowanie
 *   AbstractAuthenticationFailureEvent → nieudane logowanie
 *
 * Przy każdym zdarzeniu:
 *   1. Pobiera z bazy liczbę nieudanych prób z ostatnich 3 minut
 *   2. Wywołuje DroolsSecurityService.evaluateLoginAttempt()
 *   3. Przy udanym logowaniu — rejestruje nową sesję w user_session
 */
@Component
@RequiredArgsConstructor
public class LoginAttemptListener {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptListener.class);

    private final DroolsSecurityService  droolsSecurityService;
    private final AppUserRepository      appUserRepository;
    private final SecurityAlertRepository securityAlertRepository;
    private final UserSessionRepository  userSessionRepository;

    // ---- Udane logowanie ----

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String username = extractUsername(event.getAuthentication().getPrincipal());
        if (username == null) return;

        AppUser user = appUserRepository.findByUsername(username).orElse(null);
        if (user == null) return;

        String ip = getClientIp();
        // Liczba nieudanych prób z ostatnich 3 min (przed sukcesem — nieistotne, ale dla spójności)
        int recentFailed = securityAlertRepository.countRecentHighAlerts(user.getId(), 3);

        // Drools ocenia porę dnia (nawet dla udanego logowania)
        droolsSecurityService.evaluateLoginAttempt(
                user.getId(), username, false, ip, recentFailed);

        // Zarejestruj sesję Spring Security w tabeli user_session (audyt + na potrzeby blokad)
        registerSession(user, ip);
    }

    // ---- Nieudane logowanie ----

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String username = extractUsername(event.getAuthentication().getPrincipal());
        if (username == null) return;

        AppUser user = appUserRepository.findByUsername(username).orElse(null);
        if (user == null) {
            log.debug("[LOGIN] Nieudana próba logowania dla nieznanego użytkownika: '{}'", username);
            return;
        }

        String ip = getClientIp();
        // Pobierz liczbę nieudanych prób z ostatnich 3 minut (z bazy alertów HIGH)
        // UWAGA: używamy prostego zliczania z tabeli security_alert dla spójności.
        // Można też użyć dedykowanej tabeli failed_login_attempts — to uproszczenie.
        int recentFailed = countRecentFailedAttempts(user.getId());

        droolsSecurityService.evaluateLoginAttempt(
                user.getId(), username, true, ip, recentFailed);
    }

    // ---- Metody pomocnicze ----

    private void registerSession(AppUser user, String ip) {
        try {
            HttpServletRequest request = getCurrentRequest();
            String sessionId  = request != null ? request.getSession(false) != null
                                                  ? request.getSession(false).getId() : "UNKNOWN"
                    : "UNKNOWN";
            String userAgent  = request != null ? request.getHeader("User-Agent") : null;

            UserSession session = new UserSession();
            session.setUser(user);
            session.setSessionToken(sessionId);
            session.setLoginTime(LocalDateTime.now());
            session.setIpAddress(ip);
            session.setUserAgent(userAgent != null && userAgent.length() > 512
                    ? userAgent.substring(0, 512) : userAgent);
            session.setIsActive(true);
            userSessionRepository.save(session);

            log.debug("[SESSION] Zarejestrowano sesję {} dla '{}'", sessionId, user.getUsername());
        } catch (Exception e) {
            log.warn("[SESSION] Nie udało się zarejestrować sesji dla '{}': {}",
                    user.getUsername(), e.getMessage());
        }
    }

    /**
     * Zlicza nieudane próby logowania dla użytkownika z ostatnich 3 minut.
     * Uproszczone: liczymy alerty BRUTE_FORCE z security_alert.
     * W produkcji warto mieć osobną tabelę failed_login_attempts dla wydajności.
     */
    private int countRecentFailedAttempts(Long userId) {
        // Pobieramy alerty BRUTE_FORCE z ostatnich 3 minut jako proxy
        // Rzeczywista implementacja powinna liczyć z osobnej, szybkiej tabeli
        return securityAlertRepository.countRecentAlertsByLevel(userId, 3, "HIGH");
    }

    private String extractUsername(Object principal) {
        if (principal instanceof UserDetails ud) return ud.getUsername();
        if (principal instanceof String s)       return s;
        return null;
    }

    private String getClientIp() {
        HttpServletRequest request = getCurrentRequest();
        if (request == null) return "UNKNOWN";
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attrs =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs != null ? attrs.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.LoginAttempt;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.service.DroolsSecurityService;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.UserSession;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.SecurityAlertRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.UserSessionRepository;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Komponent nasłuchujący zdarzeń Spring Security w celu integracji z silnikiem reguł Drools
 * oraz zarządzania sesjami użytkowników.
 */
@Component
@RequiredArgsConstructor
public class LoginAttemptListener {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptListener.class);
    private final DroolsSecurityService droolsSecurityService;
    private final AppUserRepository appUserRepository;
    private final UserSessionRepository userSessionRepository;
    private final SecurityAlertRepository securityAlertRepository;

    // Lokalna pamięć podręczna do śledzenia nieudanych prób logowania
    private final Map<String, List<LocalDateTime>> failedAttempts = new ConcurrentHashMap<>();

    /**
     * Obsługa udanego logowania: weryfikacja bezpieczeństwa przez Drools i rejestracja sesji.
     */
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String username = extractUsername(event.getAuthentication().getPrincipal());
        if (username == null) return;
        AppUser user = appUserRepository.findByUsername(username).orElse(null);
        if (user == null) return;

        String ip = getClientIp();
        failedAttempts.remove(username); // Resetowanie licznika błędów po sukcesie

        LoginAttempt attempt = droolsSecurityService.evaluateLoginAttempt(user.getId(), username, false, ip, 0);

        // Natychmiastowe przerwanie sesji w przypadku wykrycia blokady przez reguły
        if ("BLOCK".equals(attempt.getActionRequired())) {
            forceLogoutImmediately();
            return;
        }

        registerSession(user, ip);
    }

    /**
     * Obsługa nieudanego logowania: aktualizacja licznika prób i ocena bezpieczeństwa przez Drools.
     */
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String username = extractUsername(event.getAuthentication().getPrincipal());
        if (username == null) return;
        AppUser user = appUserRepository.findByUsername(username).orElse(null);
        if (user == null) return;

        String ip = getClientIp();
        int recentFailed = recordAndCountFailedAttempt(username);

        droolsSecurityService.evaluateLoginAttempt(user.getId(), username, true, ip, recentFailed);
    }

    /**
     * Rejestruje nieudaną próbę w pamięci podręcznej i zwraca aktualną liczbę błędów.
     */
    private int recordAndCountFailedAttempt(String username) {
        List<LocalDateTime> attempts = failedAttempts.computeIfAbsent(username, k -> new ArrayList<>());
        LocalDateTime now = LocalDateTime.now();
        attempts.add(now);
        // Oczyszczanie prób starszych niż 3 minuty
        attempts.removeIf(time -> time.isBefore(now.minusMinutes(3)));
        return attempts.size();
    }

    /**
     * Wymusza natychmiastowe unieważnienie sesji i wyczyszczenie kontekstu bezpieczeństwa.
     */
    private void forceLogoutImmediately() {
        SecurityContextHolder.clearContext();
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
        }
    }

    /**
     * Zapisuje nową sesję użytkownika w bazie danych.
     */
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

    //

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
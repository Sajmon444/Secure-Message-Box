package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.service;

import lombok.RequiredArgsConstructor;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.AlertEscalationRequest;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.LoginAttempt;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.MessageScanRequest;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecurityAlert;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.UserSession;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.SecurityAlertRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.UserSessionRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.transaction.annotation.Propagation;

/**
 * Główny serwis integrujący Drools z logiką bezpieczeństwa aplikacji.
 *
 * Odpowiada za:
 *   1. evaluateLoginAttempt()  - analiza brute-force i pora dnia
 *   2. scanMessageContent()    - DLP dla wiadomości STANDARD
 *   3. checkEscalation()       - agregacja alertów i eskalacja do HIGH
 *   4. blockAccount()          - zapis blokady w bazie + unieważnienie sesji
 *   5. invalidateAllSessions() - wylogowanie przez Spring SessionRegistry
 *
 * Każde wywołanie Drools:
 *   - tworzy nową KieSession (stateless per-request)
 *   - wrzuca fakt
 *   - fireAllRules()
 *   - dispose() — ZAWSZE, nawet przy wyjątku (finally)
 */
@Service
@RequiredArgsConstructor
public class DroolsSecurityService {

    private static final Logger log = LoggerFactory.getLogger(DroolsSecurityService.class);

    /** Domyślny czas blokady konta (24 godziny) */
    private static final int BLOCK_DURATION_HOURS = 24;

    private final KieContainer         kieContainer;
    private final AppUserRepository    appUserRepository;
    private final SecurityAlertRepository securityAlertRepository;
    private final UserSessionRepository   userSessionRepository;
    private final SessionRegistry         sessionRegistry;

    // =========================================================
    // 1. ANALIZA PRÓBY LOGOWANIA (brute-force + pora dnia)
    // =========================================================

    /**
     * Analizuje próbę logowania przez Drools.
     * Wywoływana przez LoginAttemptListener po każdej próbie logowania.
     *
     * @param userId               ID użytkownika (app_user.id)
     * @param username             nazwa użytkownika
     * @param failed               czy logowanie się nie powiodło
     * @param ipAddress            adres IP nadawcy
     * @param recentFailedAttempts liczba nieudanych prób z ostatnich 3 min (z bazy)
     * @return LoginAttempt po odpaleniu reguł (zawiera actionRequired, alertSeverity, itd.)
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public LoginAttempt evaluateLoginAttempt(Long userId, String username,
                                             boolean failed, String ipAddress,
                                             int recentFailedAttempts) {
        LoginAttempt attempt = new LoginAttempt(
                userId,
                username,
                failed,
                 LocalDateTime.now(),
                //LocalDateTime.of(2026, 6, 11, 12, 30),
                ipAddress, recentFailedAttempts
        );

        KieSession session = kieContainer.newKieSession();
        try {
            session.insert(attempt);
            int fired = session.fireAllRules();
            log.debug("[Drools] evaluateLoginAttempt: {} reguł odpalonych dla '{}'", fired, username);
        } finally {
            session.dispose();
        }

        // Przetwórz wynik z Drools
        handleLoginAttemptResult(attempt);
        return attempt;
    }

    private void handleLoginAttemptResult(LoginAttempt attempt) {
        // Używamy .orElseThrow dla bezpieczeństwa
        AppUser user = appUserRepository.findByUsername(attempt.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found: " + attempt.getUsername()));

        switch (attempt.getActionRequired()) {
            case "BLOCK" -> {
                saveAlert(user, attempt.getAlertSeverity(), attempt.getAlertType(), attempt.getAlertDescription());
                blockAccount(user, attempt.getBlockReason(), "SECURITY_BLOCK_" + attempt.getAlertType());
            }
            case "ALERT_LOW" -> {
                saveAlert(user, attempt.getAlertSeverity(), attempt.getAlertType(), attempt.getAlertDescription());
                // Eskalacja wymaga aktualnych danych, dlatego wywołujemy ją po zapisie alertu
                checkEscalation(user);
            }
        }
    }

    // =========================================================
    // 2. DLP — SKANOWANIE TREŚCI WIADOMOŚCI (tylko STANDARD/AES)
    // =========================================================

    /**
     * Skanuje treść wiadomości STANDARD pod kątem wycieku danych (DLP).
     *
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public MessageScanRequest scanMessageContent(Long senderId, String senderUsername,
                                                 Long receiverId, String plainText) {
        MessageScanRequest req = new MessageScanRequest(senderId, senderUsername, receiverId, plainText);

        KieSession session = kieContainer.newKieSession();
        try {
            session.insert(req);
            int fired = session.fireAllRules();
            log.debug("[Drools] scanMessageContent: {} reguł odpalonych dla '{}'", fired, senderUsername);
        } finally {
            session.dispose();
        }

        // Jeśli DLP wykryło naruszenie — zapisz alert MEDIUM
        if (req.isBlocked()) {
            appUserRepository.findById(senderId).ifPresent(user -> {
                saveAlert(user, "MEDIUM", req.getAlertType(), req.getAlertDescription());
                checkEscalation(user);
                log.warn("[DLP] Wiadomość od '{}' zablokowana. Typ: {}. Opis: {}",
                        senderUsername, req.getAlertType(), req.getAlertDescription());
            });
        }

        return req;
    }

    // =========================================================
    // 3. ESKALACJA ALERTÓW
    // =========================================================

    /**
     * Sprawdza czy nowy alert powoduje eskalację i blokadę konta.
     * Wywoływana po zapisaniu każdego alertu LOW lub MEDIUM.
     */
    @Transactional
    public void checkEscalation(AppUser user) {
        // Pobierz liczniki alertów z ostatnich 10 minut
        int lowCount    = securityAlertRepository.countRecentAlertsByLevel(user.getId(), 10, "LOW");
        int mediumCount = securityAlertRepository.countRecentAlertsByLevel(user.getId(), 10, "MEDIUM");

        AlertEscalationRequest esc = new AlertEscalationRequest(
                user.getId(), user.getUsername(), lowCount, mediumCount
        );

        KieSession session = kieContainer.newKieSession();
        try {
            session.insert(esc);
            int fired = session.fireAllRules();
            log.debug("[Drools] checkEscalation: {} reguł odpalonych dla '{}'", fired, user.getUsername());
        } finally {
            session.dispose();
        }

        if (esc.isShouldEscalate()) {
            saveAlert(user, "HIGH", "ESCALATION_AGGREGATED", esc.getEscalationDescription());
            blockAccount(user, esc.getBlockReason(), "SECURITY_BLOCK_ESCALATION");
            log.warn("[SECURITY] Eskalacja alertów dla '{}'. Konto zablokowane. Powód: {}",
                    user.getUsername(), esc.getBlockReason());
        }
    }

    // =========================================================
    // 4. BLOKADA KONTA + UNIEWAŻNIENIE SESJI
    // =========================================================

    /**
     * Blokuje konto użytkownika na BLOCK_DURATION_HOURS godzin
     * i natychmiast unieważnia wszystkie jego aktywne sesje Spring Security.
     *
     * @param user               encja użytkownika do zablokowania
     * @param blockReason        czytelny powód blokady (trafia do app_user.block_reason)
     * @param invalidationReason kod powodu unieważnienia sesji (trafia do user_session.invalidation_reason)
     */
    @Transactional
    public void blockAccount(AppUser user, String blockReason, String invalidationReason) {
        // 1. Aktualizuj status konta w bazie
        LocalDateTime blockedUntil = LocalDateTime.now().plusHours(BLOCK_DURATION_HOURS);
        user.setAccountStatus("BLOCKED");
        user.setBlockedUntil(blockedUntil);
        user.setBlockReason(blockReason);
        appUserRepository.save(user);
        log.warn("[SECURITY] Konto '{}' (ID={}) zablokowane do: {}",
                user.getUsername(), user.getId(), blockedUntil);

        // 2. Unieważnij wszystkie aktywne sesje w bazie audytowej
        invalidateAllSessionsInDb(user, invalidationReason);

        // 3. Unieważnij sesje w Spring Security (wylogowanie natychmiastowe)
        invalidateSpringSecuritySessions(user.getUsername(), invalidationReason);
    }

    /**
     * Unieważnia wszystkie aktywne sesje użytkownika w tabeli user_session
     * (rekord audytowy).
     */
    private void invalidateAllSessionsInDb(AppUser user, String reason) {
        List<UserSession> activeSessions = userSessionRepository.findByUserIdAndIsActiveTrue(user.getId());
        LocalDateTime now = LocalDateTime.now();
        for (UserSession s : activeSessions) {
            s.setIsActive(false);
            s.setLogoutTime(now);
            s.setInvalidationReason(reason);
        }
        userSessionRepository.saveAll(activeSessions);
        log.info("[SESSION] Unieważniono {} sesji dla '{}' (powód: {})",
                activeSessions.size(), user.getUsername(), reason);
    }

    /**
     * Unieważnia sesje w Spring Security SessionRegistry.
     * Po wywołaniu expireNow() Spring przy następnym żądaniu użytkownika
     * przekieruje go na stronę logowania (lub zwróci 401).
     */
    private void invalidateSpringSecuritySessions(String username, String reason) {
        sessionRegistry.getAllPrincipals().stream()
                .filter(p -> p instanceof UserDetails ud && ud.getUsername().equals(username))
                .forEach(principal -> {
                    List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, false);
                    sessions.forEach(si -> {
                        si.expireNow();
                        log.info("[SESSION] Sesja Spring Security wygaszona: {} dla '{}' (powód: {})",
                                si.getSessionId(), username, reason);
                    });
                });
    }

    /**
     * Unieważnia aktualną sesję HTTP (jeśli istnieje)
     * oraz czyści SecurityContext bieżącego wątku.
     */
    private void invalidateCurrentHttpSession() {
        try {
            SecurityContextHolder.clearContext();

            ServletRequestAttributes attr =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

            if (attr != null) {
                HttpSession session = attr.getRequest().getSession(false);

                if (session != null) {
                    String sessionId = session.getId();
                    session.invalidate();

                    log.info("[SESSION] Aktualna sesja HTTP unieważniona: {}", sessionId);
                }
            }
        } catch (IllegalStateException ex) {
            log.debug("[SESSION] Sesja była już unieważniona");
        } catch (Exception ex) {
            log.error("[SESSION] Błąd podczas unieważniania aktualnej sesji HTTP", ex);
        }
    }

    // =========================================================
    // METODY POMOCNICZE
    // =========================================================

    /** Zapisuje alert bezpieczeństwa do tabeli security_alert. */
    private void saveAlert(AppUser user, String severity, String alertType, String description) {
        SecurityAlert alert = new SecurityAlert();
        alert.setUser(user);
        alert.setSeverityLevel(severity);
        alert.setAlertType(alertType);
        alert.setDescription(description);
        securityAlertRepository.save(alert);
        log.info("[ALERT] {} | {} | user={} | {}",
                severity, alertType, user.getUsername(), description);
    }

    /**
     * Sprawdza czy konto jest zablokowane i czy blokada jeszcze trwa.
     * Używane przez AppUserDetailsService i MessageService przed wykonaniem akcji.
     *
     * @return true jeśli konto jest aktualnie zablokowane
     */
    public boolean isAccountBlocked(AppUser user) {
        return user.isCurrentlyBlocked();
    }
}
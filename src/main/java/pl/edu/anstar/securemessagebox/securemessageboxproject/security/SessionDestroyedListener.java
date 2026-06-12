package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.UserSessionRepository;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class SessionDestroyedListener {

    private static final Logger log = LoggerFactory.getLogger(SessionDestroyedListener.class);
    private final UserSessionRepository userSessionRepository;

    @EventListener
    @Transactional
    public void onSessionDestroyed(HttpSessionDestroyedEvent event) {
        String sessionId = event.getId();

        userSessionRepository.findBySessionToken(sessionId).ifPresent(session -> {
            // Unikamy nadpisywania, jeśli sesja została już unieważniona przez Drools z powodu alertu HIGH
            if (session.getIsActive()) {
                session.setIsActive(false);
                session.setLogoutTime(LocalDateTime.now());
                userSessionRepository.save(session);
                log.debug("[SESSION] Sesja {} oznaczona jako nieaktywna (normalne wylogowanie/timeout)", sessionId);
            }
        });
    }
}
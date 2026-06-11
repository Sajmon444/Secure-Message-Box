package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

import java.time.LocalDateTime;

/**
 * Harmonogram automatycznego odblokowywania kont.
 *
 * Domyślna blokada konta trwa 24 godziny (ustawiana przez DroolsSecurityService).
 * Ten scheduler co 60 minut odpytuje bazę i odblokuje konta,
 * których czas blokady (blocked_until) już minął.
 *
 * Aby scheduler działał, wymagana jest adnotacja @EnableScheduling
 * na klasie głównej aplikacji lub dowolnej klasie @Configuration.
 *
 * Harmonogram: co 60 minut, opóźnienie startu 5 minut po uruchomieniu serwera.
 */
@Component
@RequiredArgsConstructor
public class AccountUnblockScheduler {

    private static final Logger log = LoggerFactory.getLogger(AccountUnblockScheduler.class);

    private final AppUserRepository appUserRepository;

    /**
     * Odblokowanie kont z wygasłą blokadą.
     * Uruchamiane co 60 minut (fixedDelay = czas od zakończenia poprzedniego wykonania).
     * initialDelay = 5 min — nie blokuj startu aplikacji.
     */
    @Scheduled(fixedDelayString = "PT60M", initialDelayString = "PT5M")
    @Transactional
    public void unblockExpiredAccounts() {
        LocalDateTime now = LocalDateTime.now();
        int count = appUserRepository.unblockExpiredAccounts(now);
        if (count > 0) {
            log.info("[SCHEDULER] Odblokowano {} kont z wygasłą blokadą (stan na: {})", count, now);
        } else {
            log.debug("[SCHEDULER] Brak kont do odblokowania (stan na: {})", now);
        }
    }
}

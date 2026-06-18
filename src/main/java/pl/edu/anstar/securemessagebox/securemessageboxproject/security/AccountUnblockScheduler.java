package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

import java.time.LocalDateTime;

/**
 * Komponent odpowiedzialny za automatyczne odblokowywanie kont użytkowników,
 * których czas blokady uległ przedawnieniu.
 */
@Component
@RequiredArgsConstructor
public class AccountUnblockScheduler {

    private static final Logger log = LoggerFactory.getLogger(AccountUnblockScheduler.class);
    private final AppUserRepository appUserRepository;

    /**
     * Inicjalizuje proces odblokowywania kont natychmiast po starcie aplikacji.
     */
    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void unblockOnStartup() {
        log.info("[SCHEDULER] Sprawdzanie wygasłych blokad podczas startu systemu...");
        unblockExpiredAccounts();
    }

    /**
     * Cyklicznie (co 60 minut) sprawdza bazę danych i odblokowuje konta
     * z wygasłym terminem blokady.
     */
    @Scheduled(fixedDelayString = "PT60M")
    @Transactional
    public void unblockExpiredAccounts() {
        int count = appUserRepository.unblockExpiredAccounts();

        if (count > 0) {
            log.info("[SCHEDULER] Odblokowano {} kont z wygasłą blokadą (stan na: {})", count, LocalDateTime.now());
        }
    }
}
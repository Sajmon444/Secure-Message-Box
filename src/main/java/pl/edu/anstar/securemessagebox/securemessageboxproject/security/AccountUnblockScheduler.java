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

@Component
@RequiredArgsConstructor
public class AccountUnblockScheduler {

    private static final Logger log = LoggerFactory.getLogger(AccountUnblockScheduler.class);
    private final AppUserRepository appUserRepository;

    // 1. Sprawdzanie i odblokowywanie NATYCHMIAST po uruchomieniu aplikacji
    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void unblockOnStartup() {
        log.info("[SCHEDULER] Sprawdzanie wygasłych blokad podczas startu systemu...");
        unblockExpiredAccounts();
    }

    // 2. Cykliczne sprawdzanie (co 60 minut)
    @Scheduled(fixedDelayString = "PT60M")
    @Transactional
    public void unblockExpiredAccounts() {
        // Wywołujemy zaktualizowaną metodę wywołującą funkcję SQL
        int count = appUserRepository.unblockExpiredAccounts();

        if (count > 0) {
            log.info("[SCHEDULER] Odblokowano {} kont z wygasłą blokadą (stan na: {})", count, LocalDateTime.now());
        }
    }
}
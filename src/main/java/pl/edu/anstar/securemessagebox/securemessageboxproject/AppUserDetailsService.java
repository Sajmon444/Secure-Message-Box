package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

import java.time.format.DateTimeFormatter;

/**
 * Implementacja UserDetailsService z obsługą blokady konta.
 *
 * Spring Security wywołuje tę klasę podczas każdej próby logowania.
 * Jeśli konto jest zablokowane (accountStatus=BLOCKED i blokada jeszcze trwa),
 * rzucamy LockedException — Spring tłumaczy to na komunikat o zablokowaniu konta
 * i przekierowuje na /login?locked=true.
 *
 * Zmiana względem oryginału:
 *   Dodano sprawdzenie isCurrentlyBlocked() przed budowaniem UserDetails.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm");

    private final AppUserRepository appUserRepository;

    public AppUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Nie znaleziono użytkownika: " + username));

        // Sprawdź czy konto jest zablokowane przez Drools
        if (appUser.isCurrentlyBlocked()) {
            String until = appUser.getBlockedUntil() != null
                    ? " Blokada do: " + appUser.getBlockedUntil().format(FMT) + "."
                    : "";
            String reason = appUser.getBlockReason() != null
                    ? " Powód: " + appUser.getBlockReason()
                    : "";
            throw new LockedException(
                    "Konto '" + username + "' jest tymczasowo zablokowane." + until + reason
            );
        }

        return User.builder()
                .username(appUser.getUsername())
                .password(appUser.getPasswordHash())
                .roles("USER")
                .build();
    }
}
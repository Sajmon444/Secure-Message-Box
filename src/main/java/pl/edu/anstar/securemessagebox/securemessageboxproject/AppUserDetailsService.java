package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

/**
 * Implementacja UserDetailsService używana przez Spring Security.
 *
 * Spring Security wywołuje tę klasę podczas każdej próby logowania.
 * Na podstawie nazwy użytkownika pobierany jest rekord z bazy danych,
 * a następnie tworzony jest obiekt UserDetails wykorzystywany
 * podczas procesu uwierzytelniania.
 *
 * Obsługa blokady konta:
 * Jeśli użytkownik jest aktualnie zablokowany
 * (np. przez mechanizm Drools lub inną logikę biznesową),
 * pole accountNonLocked zostaje ustawione na false.
 *
 * Dzięki temu Spring Security automatycznie traktuje konto
 * jako zablokowane i uniemożliwia zalogowanie użytkownika.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    public AppUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    /**
     * Ładuje dane użytkownika na potrzeby uwierzytelniania.
     *
     * @param username nazwa użytkownika podana podczas logowania
     * @return obiekt UserDetails wymagany przez Spring Security
     * @throws UsernameNotFoundException gdy użytkownik nie istnieje
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Pobranie użytkownika z bazy danych
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Nie znaleziono użytkownika: " + username));

        /*
         * Konto jest uznawane za niezablokowane tylko wtedy,
         * gdy metoda isCurrentlyBlocked() zwraca false.
         */
        boolean isAccountNonLocked = !appUser.isCurrentlyBlocked();

        /*
         * Tworzenie obiektu UserDetails używanego przez Spring Security.
         *
         * Parametry:
         * enabled                -> konto aktywne
         * accountNonExpired      -> konto nie wygasło
         * credentialsNonExpired  -> hasło nie wygasło
         * accountNonLocked       -> konto nie jest zablokowane
         * authorities            -> role/uprawnienia użytkownika
         */
        return new org.springframework.security.core.userdetails.User(
                appUser.getUsername(),
                appUser.getPasswordHash(),
                true,   // enabled
                true,   // accountNonExpired
                true,   // credentialsNonExpired
                isAccountNonLocked,
                AuthorityUtils.createAuthorityList("ROLE_USER")
        );
    }
}
package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

/**
 * Serwis realizujący ładowanie danych użytkownika dla mechanizmów uwierzytelniania Spring Security.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    public AppUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    /**
     * Wczytanie danych użytkownika z bazy danych na potrzeby procesu logowania.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Pobranie danych użytkownika z repozytorium
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Nie znaleziono użytkownika: " + username));

        // Weryfikacja statusu blokady konta
        boolean isAccountNonLocked = !appUser.isCurrentlyBlocked();

        // Budowa obiektu użytkownika Spring Security
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
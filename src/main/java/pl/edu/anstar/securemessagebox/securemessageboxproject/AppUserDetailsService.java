package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

/**
 * Implementacja UserDetailsService — Spring Security wywołuje tę klasę
 * podczas logowania, żeby pobrać dane użytkownika z bazy danych.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    public AppUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Nie znaleziono użytkownika: " + username));

        // Budujemy obiekt UserDetails ze standardowej biblioteki Spring Security.
        // passwordHash w bazie to już zaszyfrowane hasło (BCrypt), Spring sam porówna.
        return User.builder()
                .username(appUser.getUsername())
                .password(appUser.getPasswordHash())
                .roles("USER")
                .build();
    }
}

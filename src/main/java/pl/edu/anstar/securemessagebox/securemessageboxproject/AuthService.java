package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

/**
 * Serwis odpowiedzialny za rejestrację nowych użytkowników.
 * Hasło jest haszowane BCryptem przed zapisem do bazy.
 */
@Service
public class AuthService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Rejestruje nowego użytkownika.
     * @return true jeśli się udało, false jeśli nazwa użytkownika jest już zajęta
     */
    public boolean register(String username, String rawPassword) {
        if (appUserRepository.existsByUsername(username)) {
            return false; // użytkownik już istnieje
        }

        AppUser newUser = new AppUser();
        newUser.setUsername(username);
        newUser.setPasswordHash(passwordEncoder.encode(rawPassword)); // BCrypt!

        appUserRepository.save(newUser);
        return true;
    }
}

package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

import java.security.KeyPair;

/**
 * Serwis rejestracji użytkownika.
 * Przy rejestracji generowana jest para kluczy RSA:
 *   - klucz publiczny trafia do bazy (app_user.public_key)
 *   - klucz prywatny jest zwracany do kontrolera i pokazywany użytkownikowi TYLKO RAZ
 */
@Service
public class AuthService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final E2eeService e2eeService;

    public AuthService(AppUserRepository appUserRepository,
                       PasswordEncoder passwordEncoder,
                       E2eeService e2eeService) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.e2eeService = e2eeService;
    }

    /**
     * Rejestruje nowego użytkownika.
     * @return klucz prywatny RSA w Base64 (do pokazania użytkownikowi JEDEN RAZ), lub null jeśli nazwa zajęta
     */
    @Transactional
    public String register(String username, String rawPassword) throws Exception {
        if (appUserRepository.existsByUsername(username)) {
            return null; // nazwa zajęta
        }

        KeyPair keyPair = e2eeService.generateKeyPair();

        AppUser newUser = new AppUser();
        newUser.setUsername(username);
        newUser.setPasswordHash(passwordEncoder.encode(rawPassword));
        newUser.setPublicKey(e2eeService.encodePublicKey(keyPair.getPublic()));

        appUserRepository.saveAndFlush(newUser);

        // Klucz prywatny zwracamy do kontrolera — serwer go nie zapisuje
        return e2eeService.encodePrivateKey(keyPair.getPrivate());
    }
}
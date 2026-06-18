package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

import java.security.KeyPair;

/**
 * Serwis obsługujący proces rejestracji użytkowników oraz generowanie i zabezpieczanie
 * pary kluczy kryptograficznych E2EE.
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
     * Rejestracja nowego użytkownika w systemie wraz z inicjalizacją infrastruktury kluczy E2EE.
     */
    @Transactional
    public String register(String username, String rawPassword, String e2eePassword) throws Exception {
        if (appUserRepository.existsByUsername(username)) {
            return null;
        }

        // Generowanie par kluczy RSA oraz Ed25519
        KeyPair rsaKeyPair     = e2eeService.generateRsaKeyPair();
        KeyPair signingKeyPair = e2eeService.generateSigningKeyPair();

        // Generowanie soli dla funkcji wyprowadzania klucza (KDF)
        String kdfSalt = e2eeService.generateKdfSalt();

        // Szyfrowanie kluczy prywatnych hasłem E2EE
        String encRsaPrivKey     = e2eeService.encryptPrivateKey(rsaKeyPair.getPrivate(),     e2eePassword, kdfSalt);
        String encSigningPrivKey = e2eeService.encryptPrivateKey(signingKeyPair.getPrivate(), e2eePassword, kdfSalt);

        // Tworzenie obiektu nowego użytkownika
        AppUser newUser = new AppUser();
        newUser.setUsername(username);
        newUser.setPasswordHash(passwordEncoder.encode(rawPassword));
        newUser.setPublicKey(e2eeService.encodeKey(rsaKeyPair.getPublic()));
        newUser.setSigningPublicKey(e2eeService.encodeKey(signingKeyPair.getPublic()));
        newUser.setEncryptedPrivateKey(encRsaPrivKey);
        newUser.setEncryptedSigningPrivateKey(encSigningPrivKey);
        newUser.setKdfSalt(kdfSalt);

        // Zapis użytkownika w bazie danych
        appUserRepository.saveAndFlush(newUser);
        return kdfSalt;
    }
}
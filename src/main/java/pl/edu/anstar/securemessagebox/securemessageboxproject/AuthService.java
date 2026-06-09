package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

import java.security.KeyPair;

/**
 * Rejestracja użytkownika z pełnym zestawem kluczy E2EE.
 *
 * W bazie danych przechowujemy:
 *   - public_key                → klucz publiczny RSA (do szyfrowania wiadomości przez nadawcę)
 *   - signing_public_key        → klucz publiczny Ed25519 (do weryfikacji podpisów)
 *   - encrypted_private_key     → klucz prywatny RSA  zaszyfrowany PBKDF2+AES
 *   - encrypted_signing_priv_key → klucz prywatny Ed25519 zaszyfrowany PBKDF2+AES
 *   - kdf_salt                  → sól PBKDF2 (wspólna dla obu kluczy prywatnych)
 *
 * Klucze prywatne są zaszyfrowane hasłem E2EE użytkownika.
 * Bez tego hasła są bezużytecznymi danymi — nawet DBA ich nie odczyta.
 *
 * UWAGA: hasło E2EE jest NIEZALEŻNE od hasła logowania — użytkownik ustawia je
 * przy rejestracji w polu "Hasło E2EE". Serwer nigdy nie widzi jawnego hasła E2EE.
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
     * @param username    nazwa użytkownika
     * @param rawPassword hasło logowania (BCrypt)
     * @param e2eePassword hasło E2EE — INNE niż hasło logowania, chroni klucze prywatne
     * @return null jeśli nazwa zajęta, wpp kdfSalt (do pokazania użytkownikowi)
     */
    @Transactional
    public String register(String username, String rawPassword, String e2eePassword) throws Exception {
        if (appUserRepository.existsByUsername(username)) {
            return null;
        }

        KeyPair rsaKeyPair     = e2eeService.generateRsaKeyPair();
        KeyPair signingKeyPair = e2eeService.generateSigningKeyPair();

        String kdfSalt = e2eeService.generateKdfSalt();

        // Oba klucze prywatne szyfrujemy HASŁEM E2EE (nie hasłem logowania!)
        String encRsaPrivKey     = e2eeService.encryptPrivateKey(rsaKeyPair.getPrivate(),     e2eePassword, kdfSalt);
        String encSigningPrivKey = e2eeService.encryptPrivateKey(signingKeyPair.getPrivate(), e2eePassword, kdfSalt);

        AppUser newUser = new AppUser();
        newUser.setUsername(username);
        newUser.setPasswordHash(passwordEncoder.encode(rawPassword));
        newUser.setPublicKey(e2eeService.encodeKey(rsaKeyPair.getPublic()));
        newUser.setSigningPublicKey(e2eeService.encodeKey(signingKeyPair.getPublic()));
        newUser.setEncryptedPrivateKey(encRsaPrivKey);
        newUser.setEncryptedSigningPrivateKey(encSigningPrivKey);
        newUser.setKdfSalt(kdfSalt);

        appUserRepository.saveAndFlush(newUser);
        return kdfSalt; // zwracamy sól — użytkownik powinien ją zachować
    }
}
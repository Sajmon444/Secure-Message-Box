// src/main/java/pl/edu/anstar/securemessagebox/securemessageboxproject/EncryptionService.java

package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Szyfrowanie i deszyfrowanie wiadomości algorytmem AES-256-CBC.
 *
 * Hasło użytkownika + LOSOWA SÓŁ → klucz AES (PBKDF2WithHmacSHA256) → szyfrowanie wiadomości.
 *
 * Dla każdej wiadomości STANDARD generowane są:
 *   - losowe IV  (16 bajtów) → zapisywane w kolumnie secret_iv
 *   - losowa SÓŁ (16 bajtów) → zapisywane w kolumnie secret_salt
 *
 * Bez znajomości hasła, IV i soli odszyfrowanie jest niemożliwe.
 * Dzięki unikalnej soli per wiadomość nie można stosować tęczowych tablic
 * ani atakować wielu wiadomości jednocześnie tym samym słownikiem.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM   = "AES/CBC/PKCS5Padding";
    private static final String KEY_FACTORY = "PBKDF2WithHmacSHA256";
    private static final int    ITERATIONS  = 100000;
    private static final int    KEY_LENGTH  = 256;

    // ----------------------------------------------------------------
    // Generowanie losowych parametrów kryptograficznych
    // ----------------------------------------------------------------

    /**
     * Generuje losowe IV (16 bajtów) → do zapisania w kolumnie secret_iv.
     */
    public String generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * Generuje losową sól (16 bajtów) → do zapisania w kolumnie secret_salt.
     * Musi być wywołana PRZED encryptWithIv() i wynik przekazany do obu metod.
     */
    public String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // ----------------------------------------------------------------
    // Szyfrowanie
    // ----------------------------------------------------------------

    /**
     * Szyfruje tekst używając podanego IV i podanej soli (oba jako Base64).
     * Schemat wywołania w MessageService:
     *   String iv   = encryptionService.generateIv();
     *   String salt = encryptionService.generateSalt();
     *   String enc  = encryptionService.encryptWithIv(plainText, password, iv, salt);
     *   // zapisz enc, iv i salt do bazy
     */
    public String encryptWithIv(String plainText, String password,
                                String ivBase64, String saltBase64) throws Exception {
        SecretKey key = deriveKey(password, saltBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // ----------------------------------------------------------------
    // Deszyfrowanie
    // ----------------------------------------------------------------

    /**
     * Odszyfrowuje wiadomość używając IV i soli pobranych z bazy.
     */
    public String decrypt(String encryptedBase64, String password,
                          String ivBase64, String saltBase64) throws Exception {
        SecretKey key = deriveKey(password, saltBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        return new String(decrypted, "UTF-8");
    }

    // ----------------------------------------------------------------
    // Prywatne — generowanie klucza AES z hasła i losowej soli
    // ----------------------------------------------------------------

    private SecretKey deriveKey(String password, String saltBase64) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, ITERATIONS, KEY_LENGTH
        );
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
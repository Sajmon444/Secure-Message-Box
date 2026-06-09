// src/main/java/pl/edu/anstar/securemessagebox/securemessageboxproject/EncryptionService.java

package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Szyfrowanie i deszyfrowanie wiadomości STANDARD algorytmem AES-256-GCM (AEAD).
 *
 * AES-GCM zapewnia jednocześnie:
 *   - POUFNOŚĆ  — treść jest zaszyfrowana
 *   - INTEGRALNOŚĆ — 16-bajtowy tag uwierzytelniający wykryje każdą modyfikację
 *
 * Eliminuje ataki Padding Oracle i Bit-flipping, które były możliwe w trybie CBC.
 *
 * Dla każdej wiadomości generowane są niezależnie:
 *   - losowe IV   (12 bajtów) → zapisywane w kolumnie secret_iv   (Base64)
 *   - losowa SÓÓL (16 bajtów) → zapisywane w kolumnie secret_salt (Base64)
 *
 * cipher.doFinal() w trybie GCM zwraca: [szyfrogram || tag_16B].
 * Tag jest integralną częścią zaszyfrowanej treści — nie wymaga osobnej kolumny.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM   = "AES/GCM/NoPadding";
    private static final String KEY_FACTORY = "PBKDF2WithHmacSHA256";
    private static final int    ITERATIONS  = 65_536;
    private static final int    KEY_LENGTH  = 256;
    private static final int    GCM_TAG_BITS = 128;   // 16-bajtowy tag uwierzytelniający
    private static final int    IV_BYTES     = 12;    // RFC 5116: zalecane 12 bajtów dla GCM
    private static final int    SALT_BYTES   = 16;

    // ----------------------------------------------------------------
    // Generowanie losowych parametrów kryptograficznych
    // ----------------------------------------------------------------

    /**
     * Generuje losowe IV (12 bajtów) → do zapisania w kolumnie secret_iv.
     * GCM wymaga 12 bajtów (96 bitów) — to optymalny rozmiar dla tego trybu.
     */
    public String generateIv() {
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * Generuje losową sól PBKDF2 (16 bajtów) → do zapisania w kolumnie secret_salt.
     * Musi być wywołana PRZED encryptWithIv() i wynik przekazany do obu metod.
     */
    public String generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // ----------------------------------------------------------------
    // Szyfrowanie
    // ----------------------------------------------------------------

    /**
     * Szyfruje tekst używając AES-256-GCM.
     *
     * Schemat wywołania w MessageService:
     *   String iv   = encryptionService.generateIv();
     *   String salt = encryptionService.generateSalt();
     *   String enc  = encryptionService.encryptWithIv(plainText, password, iv, salt);
     *   // zapisz enc (zawiera wbudowany tag GCM), iv i salt do bazy
     *
     * Zwracana wartość Base64 zawiera: [szyfrogram || tag_16B]
     * — tag jest automatycznie dołączany przez cipher.doFinal() w trybie GCM.
     */
    public String encryptWithIv(String plainText, String password,
                                String ivBase64, String saltBase64) throws Exception {
        SecretKey key = deriveKey(password, saltBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // doFinal zwraca [szyfrogram || tag_16B] — razem jako jeden Base64
        byte[] encryptedWithTag = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedWithTag);
    }

    // ----------------------------------------------------------------
    // Deszyfrowanie
    // ----------------------------------------------------------------

    /**
     * Odszyfrowuje wiadomość AES-256-GCM.
     * GCM automatycznie weryfikuje tag przed deszyfrowaniem —
     * jeśli dane zostały zmodyfikowane, rzuca AEADBadTagException.
     */
    public String decrypt(String encryptedBase64, String password,
                          String ivBase64, String saltBase64) throws Exception {
        SecretKey key = deriveKey(password, saltBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // doFinal weryfikuje tag i odszyfrowuje — AEADBadTagException przy manipulacji
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        return new String(decrypted, "UTF-8");
    }

    // ----------------------------------------------------------------
    // Prywatne — wyprowadzanie klucza AES z hasła i losowej soli
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
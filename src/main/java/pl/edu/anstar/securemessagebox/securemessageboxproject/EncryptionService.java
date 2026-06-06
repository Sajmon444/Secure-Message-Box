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
 * Hasło użytkownika → klucz AES (PBKDF2WithHmacSHA256) → szyfrowanie wiadomości.
 * Losowe IV (16 bajtów) jest zapisywane w bazie razem z wiadomością (kolumna secret_iv).
 * Bez tego samego IV i hasła odszyfrowanie jest niemożliwe.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM     = "AES/CBC/PKCS5Padding";
    private static final String KEY_FACTORY   = "PBKDF2WithHmacSHA256";
    private static final byte[] SALT          = "SecureMsgBoxSalt".getBytes(); // stały salt — wystarczy na zaliczenie
    private static final int    ITERATIONS    = 65536;
    private static final int    KEY_LENGTH    = 256;

    // ----------------------------------------------------------------
    // Szyfrowanie
    // ----------------------------------------------------------------

    public String encrypt(String plainText, String password) throws Exception {
        SecretKey key = deriveKey(password);

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /** Zwraca losowe IV jako Base64 — musi być zapisane w bazie razem z wiadomością. */
    public String generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /** Szyfruje tekst używając konkretnego IV (podanego jako Base64). */
    public String encryptWithIv(String plainText, String password, String ivBase64) throws Exception {
        SecretKey key = deriveKey(password);
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

    public String decrypt(String encryptedBase64, String password, String ivBase64) throws Exception {
        SecretKey key = deriveKey(password);
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        return new String(decrypted, "UTF-8");
    }

    // ----------------------------------------------------------------
    // Prywatne — generowanie klucza AES z hasła
    // ----------------------------------------------------------------

    private SecretKey deriveKey(String password) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), SALT, ITERATIONS, KEY_LENGTH
        );
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
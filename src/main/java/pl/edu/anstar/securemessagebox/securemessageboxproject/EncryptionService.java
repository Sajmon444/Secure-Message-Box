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
 * Serwis realizujący szyfrowanie i deszyfrowanie wiadomości algorytmem AES-256-GCM.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM   = "AES/GCM/NoPadding";
    private static final String KEY_FACTORY = "PBKDF2WithHmacSHA256";
    private static final int    ITERATIONS  = 65_536;
    private static final int    KEY_LENGTH  = 256;
    private static final int    GCM_TAG_BITS = 128;
    private static final int    IV_BYTES     = 12;
    private static final int    SALT_BYTES   = 16;

    /**
     * Generowanie wektora inicjalizacyjnego (IV) dla trybu GCM.
     */
    public String generateIv() {
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * Generowanie losowej soli dla funkcji wyprowadzania klucza.
     */
    public String generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Szyfrowanie tekstu jawnego przy użyciu algorytmu AES-256-GCM.
     */
    public String encryptWithIv(String plainText, String password,
                                String ivBase64, String saltBase64) throws Exception {
        SecretKey key = deriveKey(password, saltBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] encryptedWithTag = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedWithTag);
    }

    /**
     * Deszyfrowanie i weryfikacja integralności danych algorytmem AES-256-GCM.
     */
    public String decrypt(String encryptedBase64, String password,
                          String ivBase64, String saltBase64) throws Exception {
        SecretKey key = deriveKey(password, saltBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        return new String(decrypted, "UTF-8");
    }

    /**
     * Wyprowadzanie klucza szyfrującego z hasła i soli za pomocą PBKDF2.
     */
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
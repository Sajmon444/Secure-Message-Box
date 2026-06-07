package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Serwis End-to-End Encryption (E2EE) oparty na RSA-2048.
 *
 * Zasada Zero-Knowledge:
 *   - Para kluczy RSA generowana jest dla każdego użytkownika podczas rejestracji.
 *   - Klucz PUBLICZNY trafia na serwer (kolumna app_user.public_key) — służy do szyfrowania.
 *   - Klucz PRYWATNY pokazywany jest użytkownikowi TYLKO RAZ i musi być przez niego zapisany.
 *     Serwer go nie przechowuje — nie może więc odszyfrować wiadomości E2EE.
 *   - Odszyfrowanie wymaga wklejenia swojego klucza prywatnego w przeglądarce.
 */
@Service
public class E2eeService {

    private static final String ALGORITHM = "RSA";
    private static final int    KEY_SIZE  = 2048;

    // ----------------------------------------------------------------
    // Generowanie pary kluczy
    // ----------------------------------------------------------------

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM);
        gen.initialize(KEY_SIZE, new SecureRandom());
        return gen.generateKeyPair();
    }

    public String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public String encodePrivateKey(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // ----------------------------------------------------------------
    // Szyfrowanie kluczem publicznym (nadawca)
    // ----------------------------------------------------------------

    public String encrypt(String plainText, String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(keyBytes));

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // ----------------------------------------------------------------
    // Deszyfrowanie kluczem prywatnym (odbiorca)
    // ----------------------------------------------------------------

    public String decrypt(String encryptedBase64, String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = KeyFactory.getInstance(ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        return new String(decrypted, "UTF-8");
    }
}
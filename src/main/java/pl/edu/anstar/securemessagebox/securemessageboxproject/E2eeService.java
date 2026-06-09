// src/main/java/pl/edu/anstar/securemessagebox/securemessageboxproject/E2eeService.java

package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * E2EE: RSA-2048 (szyfrowanie) + Ed25519 (podpis) + PBKDF2+AES-GCM (ochrona kluczy prywatnych).
 *
 * Klucze prywatne użytkowników (RSA i Ed25519) są chronione przez:
 *   PBKDF2WithHmacSHA256 (100 000 iteracji) - klucz AES-256
 *   AES-256-GCM (NoPadding, 12-bajtowy IV, 128-bitowy tag)
 *
 * Zmiana CBC - GCM eliminuje ataki Padding Oracle na przechowywane klucze prywatne.
 * Każda próba modyfikacji zaszyfrowanego klucza w bazie powoduje AEADBadTagException
 * zanim cokolwiek zostanie odszyfrowane.
 *
 * Format danych w bazie (Base64):
 *   encrypted_private_key / encrypted_signing_priv_key:
 *     [ IV_12B || szyfrogram_klucza || tag_GCM_16B ]
 *

 */
@Service
public class E2eeService {

    private static final int    RSA_KEY_SIZE   = 2048;
    private static final String RSA_CIPHER     = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String KDF_ALGORITHM  = "PBKDF2WithHmacSHA256";
    private static final int    KDF_ITERATIONS = 100_000;
    private static final int    KDF_KEY_BITS   = 256;
    private static final String AES_CIPHER     = "AES/GCM/NoPadding";   // CBC - GCM
    private static final int    GCM_TAG_BITS   = 128;                    // 16-bajtowy tag
    private static final int    IV_BYTES       = 12;                     // GCM: 12 bajtów (nie 16!)

    // =========================================================
    // Generowanie kluczy
    // =========================================================

    public KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return gen.generateKeyPair();
    }

    public KeyPair generateSigningKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        return gen.generateKeyPair();
    }

    // =========================================================
    // PBKDF2 + AES-GCM: szyfrowanie kluczy prywatnych
    // =========================================================

    public String generateKdfSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Szyfruje klucz prywatny (RSA lub Ed25519) hasłem E2EE przez PBKDF2+AES-256-GCM.
     *
     * Format wyniku (Base64):
     *   [ IV_12B || szyfrogram || tag_GCM_16B ]
     *
     * IV jest przechowywany razem z szyfrogramem — to standardowa praktyka;
     * tajność IV nie jest wymagana (tajność zapewnia klucz AES).
     */
    public String encryptPrivateKey(PrivateKey privateKey, String password, String kdfSaltBase64)
            throws Exception {
        SecretKey aesKey = deriveAesKey(password, kdfSaltBase64);

        byte[] iv = new byte[IV_BYTES];          // 12 bajtów dla GCM
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // doFinal  [szyfrogram || tag_16B]
        byte[] encryptedKeyBytes = cipher.doFinal(privateKey.getEncoded());

        // Prepend IV: [IV_12B || szyfrogram || tag_16B]
        byte[] combined = new byte[IV_BYTES + encryptedKeyBytes.length];
        System.arraycopy(iv, 0, combined, 0, IV_BYTES);
        System.arraycopy(encryptedKeyBytes, 0, combined, IV_BYTES, encryptedKeyBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Odszyfrowuje klucz prywatny RSA.
     * MUSI być używane wyłącznie dla kluczy RSA.
     */
    public PrivateKey decryptRsaPrivateKey(String encryptedBase64, String password,
                                           String kdfSaltBase64) throws Exception {
        byte[] rawKeyBytes = decryptKeyBytes(encryptedBase64, password, kdfSaltBase64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(rawKeyBytes));
    }

    /**
     * Odszyfrowuje klucz prywatny Ed25519.
     * MUSI być używane wyłącznie dla kluczy Ed25519.
     */
    public PrivateKey decryptEd25519PrivateKey(String encryptedBase64, String password,
                                               String kdfSaltBase64) throws Exception {
        byte[] rawKeyBytes = decryptKeyBytes(encryptedBase64, password, kdfSaltBase64);
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(rawKeyBytes));
    }

    /**
     * Wspólna logika AES-GCM deszyfrowania kluczy prywatnych.
     * Odczytuje IV_BYTES (12) z początku tablicy, reszta to szyfrogram+tag.
     * GCM weryfikuje tag automatycznie — AEADBadTagException przy złym haśle lub manipulacji.
     */
    private byte[] decryptKeyBytes(String encryptedBase64, String password, String kdfSaltBase64)
            throws Exception {
        SecretKey aesKey = deriveAesKey(password, kdfSaltBase64);
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);

        byte[] iv  = new byte[IV_BYTES];                           // 12 bajtów
        byte[] enc = new byte[combined.length - IV_BYTES];         // szyfrogram + tag
        System.arraycopy(combined, 0, iv, 0, IV_BYTES);
        System.arraycopy(combined, IV_BYTES, enc, 0, enc.length);

        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        return cipher.doFinal(enc);  // AEADBadTagException gdy dane zmienione lub złe hasło
    }

    // =========================================================
    // RSA: szyfrowanie / deszyfrowanie treści wiadomości E2EE
    // =========================================================

    public String rsaEncrypt(String plainText, String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(keyBytes));
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(
                cipher.doFinal(plainText.getBytes("UTF-8")));
    }

    public String rsaDecrypt(String encryptedBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(
                cipher.doFinal(Base64.getDecoder().decode(encryptedBase64)), "UTF-8");
    }

    // =========================================================
    // Ed25519: podpis i weryfikacja
    // =========================================================

    public String sign(String data, PrivateKey signingPrivateKey) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(signingPrivateKey);
        signer.update(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    public boolean verify(String data, String signatureBase64, String signingPublicKeyBase64)
            throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(signingPublicKeyBase64);
        PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(keyBytes));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(data.getBytes("UTF-8"));
        return verifier.verify(Base64.getDecoder().decode(signatureBase64));
    }

    // =========================================================
    // Kodowanie klucza publicznego do Base64
    // =========================================================

    public String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // =========================================================
    // PBKDF2 - klucz AES-256
    // =========================================================

    private SecretKey deriveAesKey(String password, String saltBase64) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, KDF_ITERATIONS, KDF_KEY_BITS);
        byte[] keyBytes = SecretKeyFactory.getInstance(KDF_ALGORITHM)
                .generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
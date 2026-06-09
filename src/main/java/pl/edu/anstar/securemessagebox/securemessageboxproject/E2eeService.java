package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * E2EE: RSA-2048 (szyfrowanie) + Ed25519 (podpis) + PBKDF2+AES (ochrona kluczy prywatnych).
 *
 * KLUCZOWA RÓŻNICA między RSA a Ed25519:
 *   - RSA klucz prywatny  → KeyFactory("RSA")  + PKCS8EncodedKeySpec
 *   - Ed25519 klucz prywatny → KeyFactory("Ed25519") + PKCS8EncodedKeySpec
 *   Te dwa algorytmy mają różne formaty kluczy — NIE można ich mieszać.
 */
@Service
public class E2eeService {

    private static final int    RSA_KEY_SIZE  = 2048;
    private static final String RSA_CIPHER    = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int    KDF_ITERATIONS = 100_000;
    private static final int    KDF_KEY_BITS   = 256;
    private static final String AES_CIPHER     = "AES/CBC/PKCS5Padding";

    // =========================================================
    // Generowanie kluczy
    // =========================================================

    public KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return gen.generateKeyPair();
    }

    public KeyPair generateSigningKeyPair() throws Exception {
        // Ed25519 — nowoczesny, szybki algorytm podpisu cyfrowego
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        return gen.generateKeyPair();
    }

    // =========================================================
    // PBKDF2 + AES: szyfrowanie kluczy prywatnych
    // =========================================================

    public String generateKdfSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /** Szyfruje dowolny klucz prywatny (RSA lub Ed25519) hasłem przez PBKDF2+AES. */
    public String encryptPrivateKey(PrivateKey privateKey, String password, String kdfSaltBase64)
            throws Exception {
        SecretKey aesKey = deriveAesKey(password, kdfSaltBase64);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] encryptedKeyBytes = cipher.doFinal(privateKey.getEncoded());

        byte[] combined = new byte[16 + encryptedKeyBytes.length];
        System.arraycopy(iv, 0, combined, 0, 16);
        System.arraycopy(encryptedKeyBytes, 0, combined, 16, encryptedKeyBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Odszyfrowuje klucz prywatny RSA (PKCS8 → RSA KeyFactory).
     * MUSI być użyte tylko dla kluczy RSA.
     */
    public PrivateKey decryptRsaPrivateKey(String encryptedBase64, String password, String kdfSaltBase64)
            throws Exception {
        byte[] rawKeyBytes = decryptKeyBytes(encryptedBase64, password, kdfSaltBase64);
        // RSA KeyFactory
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(rawKeyBytes));
    }

    /**
     * Odszyfrowuje klucz prywatny Ed25519 (PKCS8 → Ed25519 KeyFactory).
     * MUSI być użyte tylko dla kluczy Ed25519.
     */
    public PrivateKey decryptEd25519PrivateKey(String encryptedBase64, String password, String kdfSaltBase64)
            throws Exception {
        byte[] rawKeyBytes = decryptKeyBytes(encryptedBase64, password, kdfSaltBase64);
        // Ed25519 KeyFactory — różny od RSA!
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(rawKeyBytes));
    }

    /** Wspólna logika AES deszyfrowania — zwraca surowe bajty klucza. */
    private byte[] decryptKeyBytes(String encryptedBase64, String password, String kdfSaltBase64)
            throws Exception {
        SecretKey aesKey = deriveAesKey(password, kdfSaltBase64);
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);
        byte[] iv  = new byte[16];
        byte[] enc = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, enc, 0, enc.length);

        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(enc); // BadPaddingException przy złym haśle
    }

    // =========================================================
    // RSA: szyfrowanie / deszyfrowanie treści
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
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedBase64)), "UTF-8");
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
    // PBKDF2 → klucz AES
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
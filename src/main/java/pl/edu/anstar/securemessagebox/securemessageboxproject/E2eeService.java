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
 * Serwis obsługujący mechanizmy E2EE: szyfrowanie RSA, podpisy cyfrowe Ed25519
 * oraz zabezpieczenie kluczy prywatnych za pomocą PBKDF2 i AES-256-GCM.
 */
@Service
public class E2eeService {

    private static final int    RSA_KEY_SIZE   = 2048;
    private static final String RSA_CIPHER     = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String KDF_ALGORITHM  = "PBKDF2WithHmacSHA256";
    private static final int    KDF_ITERATIONS = 100_000;
    private static final int    KDF_KEY_BITS   = 256;
    private static final String AES_CIPHER     = "AES/GCM/NoPadding";
    private static final int    GCM_TAG_BITS   = 128;
    private static final int    IV_BYTES       = 12;

    /**
     * Generowanie pary kluczy RSA.
     */
    public KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return gen.generateKeyPair();
    }

    /**
     * Generowanie pary kluczy Ed25519 dla podpisów cyfrowych.
     */
    public KeyPair generateSigningKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        return gen.generateKeyPair();
    }

    /**
     * Generowanie losowej soli dla funkcji wyprowadzania klucza (KDF).
     */
    public String generateKdfSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Szyfrowanie klucza prywatnego algorytmem AES-256-GCM z wykorzystaniem hasła.
     */
    public String encryptPrivateKey(PrivateKey privateKey, String password, String kdfSaltBase64)
            throws Exception {
        SecretKey aesKey = deriveAesKey(password, kdfSaltBase64);

        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] encryptedKeyBytes = cipher.doFinal(privateKey.getEncoded());

        byte[] combined = new byte[IV_BYTES + encryptedKeyBytes.length];
        System.arraycopy(iv, 0, combined, 0, IV_BYTES);
        System.arraycopy(encryptedKeyBytes, 0, combined, IV_BYTES, encryptedKeyBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Odszyfrowanie klucza prywatnego RSA.
     */
    public PrivateKey decryptRsaPrivateKey(String encryptedBase64, String password,
                                           String kdfSaltBase64) throws Exception {
        byte[] rawKeyBytes = decryptKeyBytes(encryptedBase64, password, kdfSaltBase64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(rawKeyBytes));
    }

    /**
     * Odszyfrowanie klucza prywatnego Ed25519.
     */
    public PrivateKey decryptEd25519PrivateKey(String encryptedBase64, String password,
                                               String kdfSaltBase64) throws Exception {
        byte[] rawKeyBytes = decryptKeyBytes(encryptedBase64, password, kdfSaltBase64);
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(rawKeyBytes));
    }

    /**
     * Wspólna procedura deszyfrowania bajtów klucza przy użyciu AES-GCM.
     */
    private byte[] decryptKeyBytes(String encryptedBase64, String password, String kdfSaltBase64)
            throws Exception {
        SecretKey aesKey = deriveAesKey(password, kdfSaltBase64);
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);

        byte[] iv  = new byte[IV_BYTES];
        byte[] enc = new byte[combined.length - IV_BYTES];
        System.arraycopy(combined, 0, iv, 0, IV_BYTES);
        System.arraycopy(combined, IV_BYTES, enc, 0, enc.length);

        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        return cipher.doFinal(enc);
    }

    /**
     * Szyfrowanie treści wiadomości kluczem publicznym RSA.
     */
    public String rsaEncrypt(String plainText, String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(keyBytes));
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(
                cipher.doFinal(plainText.getBytes("UTF-8")));
    }

    /**
     * Deszyfrowanie treści wiadomości kluczem prywatnym RSA.
     */
    public String rsaDecrypt(String encryptedBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(
                cipher.doFinal(Base64.getDecoder().decode(encryptedBase64)), "UTF-8");
    }

    /**
     * Generowanie podpisu cyfrowego Ed25519.
     */
    public String sign(String data, PrivateKey signingPrivateKey) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(signingPrivateKey);
        signer.update(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    /**
     * Weryfikacja podpisu cyfrowego Ed25519.
     */
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

    /**
     * Kodowanie klucza do formatu Base64.
     */
    public String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Wyprowadzanie klucza AES (KDF) z hasła i soli.
     */
    private SecretKey deriveAesKey(String password, String saltBase64) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, KDF_ITERATIONS, KDF_KEY_BITS);
        byte[] keyBytes = SecretKeyFactory.getInstance(KDF_ALGORITHM)
                .generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
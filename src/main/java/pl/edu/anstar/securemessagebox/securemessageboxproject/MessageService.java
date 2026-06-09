package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.MessageCategory;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecretMessage;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.MessageCategoryRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.SecretMessageRepository;

import java.security.PrivateKey;
import java.util.List;

@Service
public class MessageService {

    private final SecretMessageRepository messageRepository;
    private final AppUserRepository userRepository;
    private final MessageCategoryRepository categoryRepository;
    private final EncryptionService encryptionService;
    private final E2eeService e2eeService;

    public MessageService(SecretMessageRepository messageRepository,
                          AppUserRepository userRepository,
                          MessageCategoryRepository categoryRepository,
                          EncryptionService encryptionService,
                          E2eeService e2eeService) {
        this.messageRepository = messageRepository;
        this.userRepository = userRepository;
        this.categoryRepository = categoryRepository;
        this.encryptionService = encryptionService;
        this.e2eeService = e2eeService;
    }

    // =========================================================
    // WYSYŁANIE
    // =========================================================

    /**
     * STANDARD: szyfrowanie AES, messagePassword = hasło wiadomości.
     *
     * END_TO_END_ENCRYPTED:
     *   - treść szyfrowana kluczem publicznym RSA odbiorcy
     *   - wiadomość podpisywana kluczem prywatnym Ed25519 nadawcy
     *   - e2eePassword = hasło E2EE nadawcy (odszyfrowuje jego klucz Ed25519 z bazy)
     *   - to hasło jest INNE niż hasło logowania
     */
    @Transactional
    public void sendMessage(String senderUsername, String receiverUsername,
                            String categoryName, String plainText,
                            String messagePassword, String e2eePassword) throws Exception {

        if (senderUsername.equalsIgnoreCase(receiverUsername)) {
            throw new IllegalArgumentException("Nie możesz wysłać wiadomości do siebie.");
        }

        AppUser sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new RuntimeException("Brak nadawcy"));

        AppUser receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Użytkownik \"" + receiverUsername + "\" nie istnieje."));

        MessageCategory category = categoryRepository.findByCategoryName(categoryName)
                .orElseThrow(() -> new RuntimeException("Brak kategorii: " + categoryName));

        String encryptedContent;
        String iv;
        String digitalSignature = null;

        if ("END_TO_END_ENCRYPTED".equals(categoryName)) {

            if (receiver.getPublicKey() == null) {
                throw new IllegalArgumentException(
                        "Odbiorca nie posiada kluczy E2EE. Nie można wysłać wiadomości Poufnej.");
            }

            // A. Szyfruj RSA kluczem publicznym ODBIORCY
            encryptedContent = e2eeService.rsaEncrypt(plainText, receiver.getPublicKey());
            iv = "E2EE_NO_IV";

            // B. Podpisz Ed25519 kluczem prywatnym NADAWCY
            // Używamy dedykowanej metody dla Ed25519 — NIE RSA!
            if (e2eePassword != null && !e2eePassword.isBlank()
                    && sender.getEncryptedSigningPrivateKey() != null) {
                try {
                    PrivateKey signingKey = e2eeService.decryptEd25519PrivateKey(
                            sender.getEncryptedSigningPrivateKey(),
                            e2eePassword,
                            sender.getKdfSalt()
                    );
                    digitalSignature = e2eeService.sign(encryptedContent, signingKey);
                } catch (Exception ex) {
                    throw new IllegalArgumentException(
                            "Złe hasło E2EE — nie można odszyfrować klucza podpisu. " +
                                    "Podaj hasło E2EE ustawione podczas rejestracji.");
                }
            }

        } else {
            iv = encryptionService.generateIv();
            encryptedContent = encryptionService.encryptWithIv(plainText, messagePassword, iv);
        }

        SecretMessage msg = new SecretMessage();
        msg.setSender(sender);
        msg.setReceiver(receiver);
        msg.setCategory(category);
        msg.setEncryptedContent(encryptedContent);
        msg.setSecretIv(iv);
        msg.setDigitalSignature(digitalSignature);

        messageRepository.saveAndFlush(msg);
    }

    // =========================================================
    // SKRZYNKA ODBIORCZA
    // =========================================================

    @Transactional(readOnly = true)
    public List<SecretMessage> getInbox(String username) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Brak użytkownika"));
        return messageRepository.findInboxWithDetails(user.getId());
    }

    // =========================================================
    // DESZYFROWANIE
    // =========================================================

    /**
     * STANDARD: messagePassword = hasło AES nadawcy.
     *
     * END_TO_END_ENCRYPTED: messagePassword = hasło E2EE ODBIORCY.
     *   Serwer pobiera zaszyfrowany klucz prywatny RSA odbiorcy z bazy,
     *   odszyfrowuje go przez PBKDF2+AES, deszyfruje wiadomość.
     *   Weryfikuje podpis Ed25519 nadawcy — wykrywa tampering.
     */
    @Transactional(readOnly = true)
    public DecryptResult decryptMessage(Long messageId, String messagePassword) throws Exception {
        SecretMessage msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new RuntimeException("Brak wiadomości"));

        String categoryName = msg.getCategory().getCategoryName();

        if ("END_TO_END_ENCRYPTED".equals(categoryName)) {
            AppUser receiver = msg.getReceiver();

            // Odszyfruj klucz prywatny RSA hasłem E2EE ODBIORCY
            // Używamy dedykowanej metody dla RSA — NIE Ed25519!
            PrivateKey rsaPrivateKey;
            try {
                rsaPrivateKey = e2eeService.decryptRsaPrivateKey(
                        receiver.getEncryptedPrivateKey(),
                        messagePassword,
                        receiver.getKdfSalt()
                );
            } catch (Exception ex) {
                throw new IllegalArgumentException(
                        "Złe hasło E2EE — nie można odszyfrować klucza prywatnego.");
            }

            // Weryfikuj podpis Ed25519
            boolean signaturePresent = msg.getDigitalSignature() != null
                    && !msg.getDigitalSignature().isBlank();
            boolean signatureValid   = false;

            if (signaturePresent && msg.getSender().getSigningPublicKey() != null) {
                signatureValid = e2eeService.verify(
                        msg.getEncryptedContent(),
                        msg.getDigitalSignature(),
                        msg.getSender().getSigningPublicKey()
                );
                if (!signatureValid) {
                    throw new SecurityException(
                            "WERYFIKACJA PODPISU NIEUDANA — wiadomość mogła zostać zmodyfikowana!");
                }
            }

            String plainText = e2eeService.rsaDecrypt(msg.getEncryptedContent(), rsaPrivateKey);
            return new DecryptResult(plainText, signaturePresent, signatureValid);

        } else {
            String plainText = encryptionService.decrypt(
                    msg.getEncryptedContent(), messagePassword, msg.getSecretIv());
            return new DecryptResult(plainText, false, false);
        }
    }

    public record DecryptResult(String plainText, boolean signaturePresent, boolean signatureValid) {}
}
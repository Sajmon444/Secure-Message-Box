package pl.edu.anstar.securemessagebox.securemessageboxproject;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.MessageScanRequest;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.service.DroolsSecurityService;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.MessageCategory;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecretMessage;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.MessageCategoryRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.SecretMessageRepository;

import java.security.PrivateKey;
import java.util.List;

/**
 * Serwis obsługujący operacje na wiadomościach: wysyłanie, odbiór oraz deszyfrowanie.
 */
@Service
@RequiredArgsConstructor
public class MessageService {

    private static final Logger log = LoggerFactory.getLogger(MessageService.class);

    private final DroolsSecurityService droolsSecurityService;
    private final AppUserRepository appUserRepository;
    private final MessageCategoryRepository categoryRepository;
    private final SecretMessageRepository messageRepository;
    private final EncryptionService encryptionService;
    private final E2eeService e2eeService;

    /**
     * Rekord przechowujący wynik operacji deszyfrowania wiadomości.
     */
    public record DecryptResult(String plainText, boolean signaturePresent, boolean signatureValid) {}

    /**
     * Implementacja procesu wysyłki wiadomości z integracją zabezpieczeń E2EE oraz DLP.
     */
    @Transactional
    public void sendMessage(String senderUsername, String receiverUsername, String categoryName,
                            String plainText, String msgPassword, String e2eePassword) throws Exception {

        AppUser sender = appUserRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Nadawca nie istnieje"));

        AppUser receiver = appUserRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Odbiorca nie istnieje: " + receiverUsername));

        // Weryfikacja blokady konta nadawcy
        if (droolsSecurityService.isAccountBlocked(sender)) {
            log.warn("[MESSAGE] Nadawca '{}' ma zablokowane konto — wysyłka odrzucona.", senderUsername);
            throw new IllegalArgumentException("Twoje konto jest tymczasowo zablokowane. Wysyłanie wiadomości jest niemożliwe.");
        }

        // Weryfikacja blokady konta odbiorcy
        if (droolsSecurityService.isAccountBlocked(receiver)) {
            log.info("[MESSAGE] Odbiorca '{}' ma zablokowane konto — wysyłka odrzucona.", receiverUsername);
            throw new IllegalArgumentException("Nie można wysłać wiadomości do użytkownika '" + receiverUsername + "' — konto odbiorcy jest tymczasowo niedostępne ze względów bezpieczeństwa.");
        }

        // Kontrola bezpieczeństwa treści (DLP) dla wiadomości standardowych
        if ("STANDARD".equals(categoryName)) {
            MessageScanRequest scan = droolsSecurityService.scanMessageContent(
                    sender.getId(), senderUsername, receiver.getId(), plainText);

            if (scan.isBlocked()) {
                log.warn("[DLP] Wiadomość od '{}' do '{}' zablokowana przez DLP: {}",
                        senderUsername, receiverUsername, scan.getAlertType());
                throw new IllegalArgumentException(scan.getBlockReason());
            }
        }

        MessageCategory category = categoryRepository.findByCategoryName(categoryName)
                .orElseThrow(() -> new IllegalArgumentException("Nieznana kategoria: " + categoryName));

        String iv, salt, encryptedContent, digitalSignature = null;

        // Implementacja szyfrowania dla kategorii STANDARD (AES) lub E2EE (RSA + Ed25519)
        if ("STANDARD".equals(categoryName)) {
            iv = encryptionService.generateIv();
            salt = encryptionService.generateSalt();
            encryptedContent = encryptionService.encryptWithIv(plainText, msgPassword, iv, salt);
        } else {
            if (e2eePassword == null || e2eePassword.isBlank()) {
                throw new IllegalArgumentException("Wymagane hasło E2EE do wysłania wiadomości poufnej.");
            }

            // Odszyfrowanie klucza prywatnego nadawcy dla podpisu
            PrivateKey signingPrivKey = e2eeService.decryptEd25519PrivateKey(
                    sender.getEncryptedSigningPrivateKey(), e2eePassword, sender.getKdfSalt());

            // Szyfrowanie treści kluczem publicznym odbiorcy
            encryptedContent = e2eeService.rsaEncrypt(plainText, receiver.getPublicKey());

            // Podpisanie wiadomości cyfrowo
            digitalSignature = e2eeService.sign(plainText, signingPrivKey);

            iv = "E2EE_NO_IV";
            salt = "E2EE_NO_SALT";
        }

        // Utrwalenie wiadomości w bazie danych
        SecretMessage message = new SecretMessage();
        message.setSender(sender);
        message.setReceiver(receiver);
        message.setCategory(category);
        message.setEncryptedContent(encryptedContent);
        message.setSecretIv(iv);
        message.setSecretSalt(salt);
        message.setDigitalSignature(digitalSignature);

        messageRepository.save(message);

        log.info("[MESSAGE] Wiadomość od '{}' do '{}' (kategoria: {}) wysłana pomyślnie.",
                senderUsername, receiverUsername, categoryName);
    }

    /**
     * Pobieranie skrzynki odbiorczej użytkownika.
     */
    @Transactional(readOnly = true)
    public List<SecretMessage> getInbox(String username) {
        AppUser receiver = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Nie znaleziono użytkownika"));
        return messageRepository.findInboxWithDetails(receiver.getId());
    }

    /**
     * Deszyfrowanie wiadomości w zależności od jej kategorii.
     */
    @Transactional
    public DecryptResult decryptMessage(Long messageId, String password) throws Exception {
        SecretMessage msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Nie znaleziono wiadomości"));

        String categoryName = msg.getCategory().getCategoryName();

        if ("STANDARD".equals(categoryName)) {
            // Odszyfrowanie przy użyciu algorytmu AES
            String plainText = encryptionService.decrypt(
                    msg.getEncryptedContent(), password, msg.getSecretIv(), msg.getSecretSalt());
            return new DecryptResult(plainText, false, false);

        } else {
            // Odszyfrowanie przy użyciu algorytmu RSA i weryfikacja podpisu Ed25519
            AppUser receiver = msg.getReceiver();
            AppUser sender = msg.getSender();

            // Odszyfrowanie klucza prywatnego RSA odbiorcy
            PrivateKey rsaPrivKey = e2eeService.decryptRsaPrivateKey(
                    receiver.getEncryptedPrivateKey(), password, receiver.getKdfSalt());

            // Odszyfrowanie treści wiadomości
            String plainText = e2eeService.rsaDecrypt(msg.getEncryptedContent(), rsaPrivKey);

            // Weryfikacja podpisu cyfrowego nadawcy
            boolean signaturePresent = msg.getDigitalSignature() != null;
            boolean signatureValid = false;

            if (signaturePresent) {
                signatureValid = e2eeService.verify(
                        plainText, msg.getDigitalSignature(), sender.getSigningPublicKey());
            }

            return new DecryptResult(plainText, signaturePresent, signatureValid);
        }
    }
}
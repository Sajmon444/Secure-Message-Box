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

@Service
@RequiredArgsConstructor
public class MessageService {

    private static final Logger log = LoggerFactory.getLogger(MessageService.class);

    private final DroolsSecurityService droolsSecurityService;
    private final AppUserRepository appUserRepository;
    private final MessageCategoryRepository categoryRepository;
    private final SecretMessageRepository messageRepository;
    private final EncryptionService encryptionService;
    private final E2eeService e2eeService; // Dodano brakujący serwis E2EE

    // =================================================================================
    // REKORD POMOCNICZY
    // =================================================================================

    public record DecryptResult(String plainText, boolean signaturePresent, boolean signatureValid) {}

    // =================================================================================
    // WYSYŁANIE WIADOMOŚCI (Integracja E2EE + Drools DLP)
    // =================================================================================

    @Transactional
    public void sendMessage(String senderUsername, String receiverUsername, String categoryName,
                            String plainText, String msgPassword, String e2eePassword) throws Exception {

        AppUser sender = appUserRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Nadawca nie istnieje"));

        AppUser receiver = appUserRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException("Odbiorca nie istnieje: " + receiverUsername));

        // ---- 1. Sprawdź blokadę nadawcy ----
        if (droolsSecurityService.isAccountBlocked(sender)) {
            log.warn("[MESSAGE] Nadawca '{}' ma zablokowane konto — wysyłka odrzucona.", senderUsername);
            throw new IllegalArgumentException("Twoje konto jest tymczasowo zablokowane. Wysyłanie wiadomości jest niemożliwe.");
        }

        // ---- 2. Sprawdź blokadę odbiorcy ----
        if (droolsSecurityService.isAccountBlocked(receiver)) {
            log.info("[MESSAGE] Odbiorca '{}' ma zablokowane konto — wysyłka odrzucona.", receiverUsername);
            throw new IllegalArgumentException("Nie można wysłać wiadomości do użytkownika '" + receiverUsername + "' — konto odbiorcy jest tymczasowo niedostępne ze względów bezpieczeństwa.");
        }

        // ---- 3. DLP — tylko dla wiadomości STANDARD (AES) ----
        if ("STANDARD".equals(categoryName)) {
            MessageScanRequest scan = droolsSecurityService.scanMessageContent(
                    sender.getId(), senderUsername, receiver.getId(), plainText);

            if (scan.isBlocked()) {
                log.warn("[DLP] Wiadomość od '{}' do '{}' zablokowana przez DLP: {}",
                        senderUsername, receiverUsername, scan.getAlertType());
                // Zmieniono na rzucenie wyjątku, aby Controller mógł to przechwycić w bloku catch
                throw new IllegalArgumentException(scan.getBlockReason());
            }
        }

        // ---- 4. Szyfrowanie (AES lub RSA+Ed25519) ----
        MessageCategory category = categoryRepository.findByCategoryName(categoryName)
                .orElseThrow(() -> new IllegalArgumentException("Nieznana kategoria: " + categoryName));

        String iv, salt, encryptedContent, digitalSignature = null;

        if ("STANDARD".equals(categoryName)) {
            iv = encryptionService.generateIv();
            salt = encryptionService.generateSalt();
            encryptedContent = encryptionService.encryptWithIv(plainText, msgPassword, iv, salt);
        } else {
            // Logika dla END_TO_END_ENCRYPTED
            if (e2eePassword == null || e2eePassword.isBlank()) {
                throw new IllegalArgumentException("Wymagane hasło E2EE do wysłania wiadomości poufnej.");
            }

            // 4a. Odszyfrowanie klucza prywatnego nadawcy w celu złożenia podpisu
            PrivateKey signingPrivKey = e2eeService.decryptEd25519PrivateKey(
                    sender.getEncryptedSigningPrivateKey(), e2eePassword, sender.getKdfSalt());

            // 4b. Szyfrowanie treści kluczem publicznym odbiorcy
            encryptedContent = e2eeService.rsaEncrypt(plainText, receiver.getPublicKey());

            // 4c. Wygenerowanie podpisu cyfrowego Ed25519 z jawnej treści
            digitalSignature = e2eeService.sign(plainText, signingPrivKey);

            iv = "E2EE_NO_IV";
            salt = "E2EE_NO_SALT";
        }

        // ---- 5. Zapis w bazie ----
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

    // =================================================================================
    // SKRZYNKA ODBIORCZA I DESZYFROWANIE
    // =================================================================================

    @Transactional(readOnly = true)
    public List<SecretMessage> getInbox(String username) {
        AppUser receiver = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Nie znaleziono użytkownika"));
        return messageRepository.findInboxWithDetails(receiver.getId());
    }

    @Transactional
    public DecryptResult decryptMessage(Long messageId, String password) throws Exception {
        SecretMessage msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new IllegalArgumentException("Nie znaleziono wiadomości"));

        String categoryName = msg.getCategory().getCategoryName();

        if ("STANDARD".equals(categoryName)) {
            // Odszyfrowanie AES
            String plainText = encryptionService.decrypt(
                    msg.getEncryptedContent(), password, msg.getSecretIv(), msg.getSecretSalt());
            return new DecryptResult(plainText, false, false);

        } else {
            // Odszyfrowanie E2EE (RSA)
            AppUser receiver = msg.getReceiver();
            AppUser sender = msg.getSender();

            // 1. Odszyfrowanie klucza prywatnego RSA odbiorcy hasłem E2EE
            PrivateKey rsaPrivKey = e2eeService.decryptRsaPrivateKey(
                    receiver.getEncryptedPrivateKey(), password, receiver.getKdfSalt());

            // 2. Odszyfrowanie treści wiadomości
            String plainText = e2eeService.rsaDecrypt(msg.getEncryptedContent(), rsaPrivKey);

            // 3. Weryfikacja podpisu nadawcy (Ed25519)
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
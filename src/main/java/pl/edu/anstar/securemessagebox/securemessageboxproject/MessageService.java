package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.MessageCategory;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecretMessage;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.MessageCategoryRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.SecretMessageRepository;

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

    /**
     * Wysyła wiadomość. Odbiorcę podajemy jako nazwę użytkownika (pole tekstowe).
     * Rzuca IllegalArgumentException jeśli odbiorca nie istnieje.
     *
     * Kategoria STANDARD    → AES-256-CBC (hasło symetryczne podane przez nadawcę)
     * Kategoria END_TO_END_ENCRYPTED → RSA-2048 (szyfrowanie kluczem publicznym odbiorcy)
     */
    @Transactional
    public void sendMessage(String senderUsername, String receiverUsername,
                            String categoryName, String plainText,
                            String messagePassword) throws Exception {

        if (senderUsername.equalsIgnoreCase(receiverUsername)) {
            throw new IllegalArgumentException("Nie możesz wysłać wiadomości do siebie.");
        }

        AppUser sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new RuntimeException("Brak nadawcy"));

        // Szukamy odbiorcy po nazwie — jeśli nie istnieje, rzucamy czytelny wyjątek
        AppUser receiver = userRepository.findByUsername(receiverUsername)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Użytkownik \"" + receiverUsername + "\" nie istnieje."));

        MessageCategory category = categoryRepository.findByCategoryName(categoryName)
                .orElseThrow(() -> new RuntimeException("Brak kategorii: " + categoryName));

        String encryptedContent;
        String iv;

        if ("END_TO_END_ENCRYPTED".equals(categoryName)) {
            // E2EE: szyfrujemy kluczem PUBLICZNYM odbiorcy
            // Serwer nie ma klucza prywatnego — nie może odszyfrować
            if (receiver.getPublicKey() == null) {
                throw new IllegalArgumentException(
                        "Odbiorca nie posiada klucza publicznego (stare konto). Nie można wysłać wiadomości E2EE.");
            }
            encryptedContent = e2eeService.encrypt(plainText, receiver.getPublicKey());
            iv = "E2EE_NO_IV"; // RSA nie używa IV — wstawiamy placeholder
        } else {
            // STANDARD: szyfrujemy AES kluczem symetrycznym (hasło nadawcy)
            iv = encryptionService.generateIv();
            encryptedContent = encryptionService.encryptWithIv(plainText, messagePassword, iv);
        }

        SecretMessage msg = new SecretMessage();
        msg.setSender(sender);
        msg.setReceiver(receiver);
        msg.setCategory(category);
        msg.setEncryptedContent(encryptedContent);
        msg.setSecretIv(iv);

        messageRepository.saveAndFlush(msg);
    }

    /** Skrzynka odbiorcza — JOIN FETCH zapobiega LazyInitializationException. */
    @Transactional(readOnly = true)
    public List<SecretMessage> getInbox(String username) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Brak użytkownika"));
        return messageRepository.findInboxWithDetails(user.getId());
    }

    /**
     * Deszyfrowanie wiadomości.
     * STANDARD          → messagePassword = hasło AES nadawcy
     * END_TO_END_ENCRYPTED → messagePassword = klucz prywatny RSA odbiorcy (Base64)
     */
    @Transactional(readOnly = true)
    public String decryptMessage(Long messageId, String messagePassword) throws Exception {
        SecretMessage msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new RuntimeException("Brak wiadomości"));

        String categoryName = msg.getCategory().getCategoryName();

        if ("END_TO_END_ENCRYPTED".equals(categoryName)) {
            // messagePassword to tutaj klucz prywatny RSA odbiorcy
            return e2eeService.decrypt(msg.getEncryptedContent(), messagePassword);
        } else {
            // STANDARD — AES z IV
            return encryptionService.decrypt(msg.getEncryptedContent(), messagePassword, msg.getSecretIv());
        }
    }
}
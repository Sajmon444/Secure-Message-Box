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

    public MessageService(SecretMessageRepository messageRepository,
                          AppUserRepository userRepository,
                          MessageCategoryRepository categoryRepository,
                          EncryptionService encryptionService) {
        this.messageRepository = messageRepository;
        this.userRepository = userRepository;
        this.categoryRepository = categoryRepository;
        this.encryptionService = encryptionService;
    }

    /** Wysyła zaszyfrowaną wiadomość. */
    @Transactional
    public void sendMessage(String senderUsername, Long receiverId,
                            String categoryName, String plainText,
                            String messagePassword) throws Exception {

        AppUser sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new RuntimeException("Brak nadawcy"));

        AppUser receiver = userRepository.findById(receiverId)
                .orElseThrow(() -> new RuntimeException("Brak odbiorcy"));

        MessageCategory category = categoryRepository.findByCategoryName(categoryName)
                .orElseThrow(() -> new RuntimeException("Brak kategorii: " + categoryName));

        // Generujemy IV i szyfrujemy
        String iv = encryptionService.generateIv();
        String encrypted = encryptionService.encryptWithIv(plainText, messagePassword, iv);

        SecretMessage msg = new SecretMessage();
        msg.setSender(sender);
        msg.setReceiver(receiver);
        msg.setCategory(category);
        msg.setEncryptedContent(encrypted);
        msg.setSecretIv(iv); // zapisujemy IV w bazie

        messageRepository.saveAndFlush(msg);
    }

    /** Pobiera wiadomości dla zalogowanego użytkownika (skrzynka odbiorcza). */
    public List<SecretMessage> getInbox(String username) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Brak użytkownika"));
        return messageRepository.findByReceiverIdOrderByCreatedAtDesc(user.getId());
    }

    /** Deszyfruje konkretną wiadomość. Rzuca wyjątek jeśli hasło złe. */
    public String decryptMessage(Long messageId, String messagePassword) throws Exception {
        SecretMessage msg = messageRepository.findById(messageId)
                .orElseThrow(() -> new RuntimeException("Brak wiadomości"));
        return encryptionService.decrypt(msg.getEncryptedContent(), messagePassword, msg.getSecretIv());
    }

    /** Lista wszystkich użytkowników (do wyboru odbiorcy). */
    public List<AppUser> getAllUsers() {
        return userRepository.findAll();
    }
}
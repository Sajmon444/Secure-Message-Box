package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecretMessage;
import java.util.List;

public interface SecretMessageRepository extends JpaRepository<SecretMessage, Long> {
    List<SecretMessage> findByReceiverIdOrderByCreatedAtDesc(Long receiverId);

    List<SecretMessage> findBySenderIdOrderByCreatedAtDesc(Long senderId);
}
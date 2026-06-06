package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecretMessage;

import java.util.List;

public interface SecretMessageRepository extends JpaRepository<SecretMessage, Long> {

    // Oryginalne metody (zostawione dla zgodności)
    List<SecretMessage> findByReceiverIdOrderByCreatedAtDesc(Long receiverId);
    List<SecretMessage> findBySenderIdOrderByCreatedAtDesc(Long senderId);

    /**
     * Skrzynka odbiorcza z JOIN FETCH — ładuje sender, receiver i category
     * w jednym zapytaniu SQL, żeby uniknąć LazyInitializationException
     * gdy Thymeleaf próbuje odczytać msg.sender.username poza sesją Hibernate.
     */
    @Query("SELECT m FROM SecretMessage m " +
            "JOIN FETCH m.sender " +
            "JOIN FETCH m.receiver " +
            "JOIN FETCH m.category " +
            "WHERE m.receiver.id = :receiverId " +
            "ORDER BY m.createdAt DESC")
    List<SecretMessage> findInboxWithDetails(@Param("receiverId") Long receiverId);
}
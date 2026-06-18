package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecretMessage;

import java.util.List;

/**
 * Repozytorium JPA obsługujące operacje na wiadomościach w systemie.
 */
public interface SecretMessageRepository extends JpaRepository<SecretMessage, Long> {

    /**
     * Pobiera listę wiadomości odebranych przez użytkownika, posortowaną od najnowszej.
     */
    List<SecretMessage> findByReceiverIdOrderByCreatedAtDesc(Long receiverId);

    /**
     * Pobiera listę wiadomości wysłanych przez użytkownika, posortowaną od najnowszej.
     */
    List<SecretMessage> findBySenderIdOrderByCreatedAtDesc(Long senderId);

    /**
     * Pobiera zawartość skrzynki odbiorczej wraz z załadowanymi relacjami (nadawca, odbiorca, kategoria).
     * Wykorzystuje JOIN FETCH w celu uniknięcia problemu LazyInitializationException.
     */
    @Query("SELECT m FROM SecretMessage m " +
            "JOIN FETCH m.sender " +
            "JOIN FETCH m.receiver " +
            "JOIN FETCH m.category " +
            "WHERE m.receiver.id = :receiverId " +
            "ORDER BY m.createdAt DESC")
    List<SecretMessage> findInboxWithDetails(@Param("receiverId") Long receiverId);
}
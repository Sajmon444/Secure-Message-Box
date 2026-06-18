package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.UserSession;
import java.util.List;
import java.util.Optional;

/**
 * Repozytorium JPA do zarządzania sesjami użytkowników w bazie danych.
 */
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    /**
     * Wyszukuje sesję na podstawie unikalnego tokena sesji.
     */
    Optional<UserSession> findBySessionToken(String sessionToken);

    /**
     * Pobiera listę wszystkich aktywnych sesji dla określonego użytkownika.
     */
    List<UserSession> findByUserIdAndIsActiveTrue(Long userId);

    /**
     * Usuwa wszystkie sesje powiązane z danym identyfikatorem użytkownika.
     */
    void deleteByUserId(Long userId);
}
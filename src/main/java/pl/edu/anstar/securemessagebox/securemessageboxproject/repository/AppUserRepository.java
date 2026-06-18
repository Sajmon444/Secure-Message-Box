package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;

import java.util.List;
import java.util.Optional;

/**
 * Repozytorium JPA do zarządzania użytkownikami systemu, obejmujące operacje na kontach
 * oraz logikę związaną z ich blokowaniem i odblokowywaniem.
 */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    /**
     * Wyszukuje użytkownika na podstawie jego unikalnej nazwy.
     */
    Optional<AppUser> findByUsername(String username);

    /**
     * Sprawdza, czy użytkownik o danej nazwie już istnieje w bazie.
     */
    boolean existsByUsername(String username);

    /**
     * Pobiera listę wszystkich aktualnie zablokowanych użytkowników,
     * dla których określono czas wygaśnięcia blokady.
     */
    @Query("SELECT u FROM AppUser u WHERE u.accountStatus = 'BLOCKED' AND u.blockedUntil IS NOT NULL")
    List<AppUser> findAllBlockedWithExpiry();

    /**
     * Wykonuje zbiorcze odblokowanie kont z wygasłym terminem blokady za pomocą funkcji SQL.
     * Zwraca liczbę kont, które zostały przywrócone do aktywności.
     */
    @Query(value = "SELECT fn_unblock_expired_accounts()", nativeQuery = true)
    int unblockExpiredAccounts();
}
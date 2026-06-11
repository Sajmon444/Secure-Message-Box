package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);

    // ---- Nowe metody związane z blokadą kont ----

    /** Zwraca wszystkich aktualnie zablokowanych użytkowników (do harmonogramu odblokowywania). */
    @Query("SELECT u FROM AppUser u WHERE u.accountStatus = 'BLOCKED' AND u.blockedUntil IS NOT NULL")
    List<AppUser> findAllBlockedWithExpiry();

    /**
     * Zbiorcze odblokowanie kont z wygasłą blokadą.
     * Wywoływane przez AccountUnblockScheduler co godzinę.
     * Zwraca liczbę odblokowanych kont.
     */
    @Modifying
    @Query("UPDATE AppUser u SET u.accountStatus = 'ACTIVE', " +
            "u.blockedUntil = NULL, u.blockReason = NULL " +
            "WHERE u.accountStatus = 'BLOCKED' " +
            "  AND u.blockedUntil IS NOT NULL " +
            "  AND u.blockedUntil <= :now")
    int unblockExpiredAccounts(@Param("now") LocalDateTime now);
}
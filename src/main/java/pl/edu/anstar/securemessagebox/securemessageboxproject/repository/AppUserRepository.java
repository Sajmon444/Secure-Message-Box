package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;

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
     * Zbiorcze odblokowanie kont z wygasłą blokadą za pomocą natywnej funkcji SQL.
     * Wywoływane przez AccountUnblockScheduler co godzinę.
     * Zwraca liczbę odblokowanych kont.
     */
    @Query(value = "SELECT fn_unblock_expired_accounts()", nativeQuery = true)
    int unblockExpiredAccounts();
}
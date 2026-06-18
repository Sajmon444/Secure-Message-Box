package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.ActiveSecurityAlertView;
import java.util.List;

/**
 * Repozytorium JPA do odczytu widoku bazy danych prezentującego aktualnie aktywne alerty bezpieczeństwa.
 */
public interface ActiveSecurityAlertViewRepository extends JpaRepository<ActiveSecurityAlertView, Long> {

    /**
     * Pobiera listę aktywnych alertów przypisanych do konkretnego użytkownika.
     */
    List<ActiveSecurityAlertView> findByUsername(String username);
}
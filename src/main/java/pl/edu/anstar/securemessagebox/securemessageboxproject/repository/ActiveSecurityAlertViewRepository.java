package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.ActiveSecurityAlertView;
import java.util.List;

public interface ActiveSecurityAlertViewRepository extends JpaRepository<ActiveSecurityAlertView, Long> {
    List<ActiveSecurityAlertView> findByUsername(String username);
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.UserSession;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findBySessionToken(String sessionToken);
    List<UserSession> findByUserIdAndIsActiveTrue(Long userId);
    void deleteByUserId(Long userId);
}
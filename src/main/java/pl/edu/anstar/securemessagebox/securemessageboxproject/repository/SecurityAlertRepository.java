package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecurityAlert;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repozytorium JPA do obsługi alertów bezpieczeństwa, integrujące logikę zapytań
 * z silnikiem reguł Drools oraz widokami administracyjnymi.
 */
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    /**
     * Zlicza liczbę alertów o określonym poziomie istotności dla danego użytkownika
     * w wybranym przedziale czasowym (wykorzystuje funkcję bazodanową).
     */
    @Query(value = "SELECT fn_count_recent_alerts_by_level(:userId, :minutes, :level)", nativeQuery = true)
    int countRecentAlertsByLevel(@Param("userId")  Long userId,
                                 @Param("minutes") int minutes,
                                 @Param("level")   String level);

    /**
     * Pobiera wszystkie alerty dla użytkownika, posortowane od najnowszego.
     */
    List<SecurityAlert> findByUserIdOrderByTimestampDesc(Long userId);

    /**
     * Pobiera alerty dla użytkownika o konkretnym poziomie istotności, posortowane od najnowszego.
     */
    List<SecurityAlert> findByUserIdAndSeverityLevelOrderByTimestampDesc(Long userId, String severityLevel);

    /**
     * Pobiera alerty dla użytkownika o konkretnym typie, posortowane od najnowszego.
     */
    List<SecurityAlert> findByUserIdAndAlertTypeOrderByTimestampDesc(Long userId, String alertType);

    /**
     * Pobiera listę alertów użytkownika zarejestrowanych po określonym czasie, posortowaną chronologicznie.
     */
    @Query("SELECT a FROM SecurityAlert a WHERE a.user.id = :userId AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<SecurityAlert> findRecentByUserId(@Param("userId") Long userId, @Param("since") LocalDateTime since);
}
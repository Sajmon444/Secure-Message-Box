package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecurityAlert;

import java.time.LocalDateTime;
import java.util.List;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    // ---- Zapytania dla eskalacji (używane przez DroolsSecurityService) ----

    /**
     * Zlicza alerty danego poziomu dla użytkownika z ostatnich N minut.
     * Używane przez checkEscalation() do oceny progów eskalacji.
     * Deleguje do nowej funkcji fn_count_recent_alerts_by_level().
     */
    @Query(value = "SELECT fn_count_recent_alerts_by_level(:userId, :minutes, :level)",
            nativeQuery = true)
    int countRecentAlertsByLevel(@Param("userId")  Long userId,
                                 @Param("minutes") int minutes,
                                 @Param("level")   String level);

    /**
     * Zachowana dla zgodności wstecznej — zlicza alerty HIGH.
     * Deleguje do fn_count_recent_alerts() (która woła fn_count_recent_alerts_by_level z HIGH).
     */
    @Query(value = "SELECT fn_count_recent_alerts(:userId, :minutes)", nativeQuery = true)
    int countRecentHighAlerts(@Param("userId") Long userId, @Param("minutes") int minutes);

    // ---- Zapytania diagnostyczne / widok admina ----

    List<SecurityAlert> findByUserIdOrderByTimestampDesc(Long userId);

    List<SecurityAlert> findByUserIdAndSeverityLevelOrderByTimestampDesc(Long userId, String severityLevel);

    List<SecurityAlert> findByUserIdAndAlertTypeOrderByTimestampDesc(Long userId, String alertType);

    /**
     * Alerty z ostatnich N minut dla danego użytkownika (do diagnostyki).
     */
    @Query("SELECT a FROM SecurityAlert a " +
            "WHERE a.user.id = :userId " +
            "  AND a.timestamp >= :since " +
            "ORDER BY a.timestamp DESC")
    List<SecurityAlert> findRecentByUserId(@Param("userId") Long userId,
                                           @Param("since")  LocalDateTime since);
}
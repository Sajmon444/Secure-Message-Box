package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.SecurityAlert;
import java.util.List;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {


    @Query(value = "SELECT fn_count_recent_alerts(:userId, :minutes)", nativeQuery = true)
    int countRecentHighAlerts(@Param("userId") Long userId, @Param("minutes") int minutes);


    List<SecurityAlert> findByUserIdAndSeverityLevelOrderByTimestampDesc(Long userId, String severityLevel);
}
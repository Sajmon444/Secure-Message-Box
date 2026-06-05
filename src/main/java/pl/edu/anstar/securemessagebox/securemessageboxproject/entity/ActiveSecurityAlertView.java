package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Immutable;
import java.time.LocalDateTime;

@Entity
@Table(name = "v_active_security_alerts")
@Immutable
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ActiveSecurityAlertView {

    @Id
    private Long id;

    private String username;

    private String description;

    private String severityLevel;

    private LocalDateTime timestamp;
}
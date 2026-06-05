package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Entity
@Table(name = "app_user")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq_gen")
    @SequenceGenerator(name = "user_seq_gen", sequenceName = "user_seq", allocationSize = 1)
    private Long id;

    @Column(unique = true, nullable = false, length = 255)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;


    @OneToMany(mappedBy = "sender", fetch = FetchType.LAZY)
    private List<SecretMessage> sentMessages;

    @OneToMany(mappedBy = "receiver", fetch = FetchType.LAZY)
    private List<SecretMessage> receivedMessages;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<SecurityAlert> alerts;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<UserSession> sessions;
}
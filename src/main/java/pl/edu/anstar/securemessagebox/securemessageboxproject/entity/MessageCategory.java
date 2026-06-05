package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Entity
@Table(name = "message_category")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessageCategory {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "message_category_seq_gen")
    @SequenceGenerator(name = "message_category_seq_gen", sequenceName = "message_category_seq", allocationSize = 1)
    private Long id;

    @Column(name = "category_name", unique = true, nullable = false, length = 50)
    private String categoryName;

    @OneToMany(mappedBy = "category", fetch = FetchType.LAZY)
    private List<SecretMessage> messages;
}
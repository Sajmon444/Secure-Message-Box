package pl.edu.anstar.securemessagebox.securemessageboxproject.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

/**
 * Encja reprezentująca kategorię wiadomości w systemie.
 * Określa typ zabezpieczeń lub przeznaczenie wiadomości (np. STANDARD, END_TO_END_ENCRYPTED).
 */
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

    /** Unikalna nazwa kategorii wiadomości (np. "STANDARD", "E2EE"). */
    @Column(name = "category_name", unique = true, nullable = false, length = 50)
    private String categoryName;

    /** Relacja z wiadomościami przypisanymi do tej kategorii. */
    @OneToMany(mappedBy = "category", fetch = FetchType.LAZY)
    private List<SecretMessage> messages;
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.MessageCategory;
import java.util.Optional;

/**
 * Repozytorium JPA do obsługi kategorii wiadomości w systemie.
 */
public interface MessageCategoryRepository extends JpaRepository<MessageCategory, Long> {

    /**
     * Wyszukuje kategorię wiadomości na podstawie jej nazwy.
     */
    Optional<MessageCategory> findByCategoryName(String categoryName);
}
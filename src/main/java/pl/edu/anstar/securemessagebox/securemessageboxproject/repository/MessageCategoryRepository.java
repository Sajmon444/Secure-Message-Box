package pl.edu.anstar.securemessagebox.securemessageboxproject.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.MessageCategory;
import java.util.Optional;

public interface MessageCategoryRepository extends JpaRepository<MessageCategory, Long> {
    Optional<MessageCategory> findByCategoryName(String categoryName);
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Fakt Drools reprezentujący żądanie wysłania wiadomości STANDARD (AES).

 *   blocked=false - wiadomość może być wysłana
 *   blocked=true - wiadomość ZABLOKOWANA, użytkownik otrzymuje komunikat z blockReason
 */
@Data
@NoArgsConstructor
public class MessageScanRequest {

    /** ID nadawcy (app_user.id) */
    private Long senderId;

    /** Nazwa nadawcy (do logów) */
    private String senderUsername;

    /** ID odbiorcy (app_user.id) */
    private Long receiverId;


    private String plainTextContent;

    // ---- Pola wypełniane przez Drools ----

    /**
     * true - wiadomość jest ZABLOKOWANA i nie może być wysłana.
     * Reguła ustawia ten flag gdy wykryje naruszenie DLP.
     */
    private boolean blocked = false;

    /** Opis powodu blokady wyświetlany użytkownikowi (w komunikacie błędu UI). */
    private String blockReason;

    /** Typ alertu DLP zgodny z CHECK constraint: DLP_SENSITIVE_KEYWORD,
     *  DLP_PESEL_PATTERN, DLP_CARD_PATTERN, DLP_LINK_DETECTED */
    private String alertType;

    /** Opis alertu zapisywany do tabeli security_alert */
    private String alertDescription;

    public MessageScanRequest(Long senderId, String senderUsername,
                              Long receiverId, String plainTextContent) {
        this.senderId = senderId;
        this.senderUsername = senderUsername;
        this.receiverId = receiverId;
        this.plainTextContent = plainTextContent;
    }
}
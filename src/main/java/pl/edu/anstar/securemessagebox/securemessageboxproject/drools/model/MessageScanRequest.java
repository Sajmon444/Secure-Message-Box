package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Fakt Drools reprezentujący żądanie wysłania wiadomości STANDARD (AES).
 *
 * WAŻNE: Ten fakt jest tworzony TYLKO dla wiadomości kategorii STANDARD.
 * Wiadomości END_TO_END_ENCRYPTED (E2EE) są WYŁĄCZONE z skanowania DLP —
 * serwer nie ma dostępu do ich odszyfrowanej treści i nie wolno ich analizować.
 *
 * Drools sprawdza plainTextContent pod kątem:
 *   - Słów kluczowych: pesel, hasło, haslo, karta kredytowa, pin
 *     → alert MEDIUM, typ DLP_SENSITIVE_KEYWORD
 *   - Ciągu dokładnie 11 cyfr (wzorzec PESEL)
 *     → alert MEDIUM, typ DLP_PESEL_PATTERN
 *   - Ciągu dokładnie 16 cyfr (wzorzec karty kredytowej)
 *     → alert MEDIUM, typ DLP_CARD_PATTERN
 *   - Linków (http://, https://, www.)
 *     → alert MEDIUM, typ DLP_LINK_DETECTED
 *
 * Po odpaleniu reguł:
 *   blocked=false → wiadomość może być wysłana
 *   blocked=true  → wiadomość ZABLOKOWANA, użytkownik otrzymuje komunikat z blockReason
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

    /**
     * Odszyfrowana treść wiadomości w pamięci RAM — NIGDY nie jest zapisywana
     * do bazy danych w tej formie. Drools skanuje wyłącznie ten obiekt w pamięci.
     * Pole jest transient z perspektywy bazy — nie trafia do żadnej kolumny.
     */
    private String plainTextContent;

    // ---- Pola wypełniane przez Drools ----

    /**
     * true → wiadomość jest ZABLOKOWANA i nie może być wysłana.
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
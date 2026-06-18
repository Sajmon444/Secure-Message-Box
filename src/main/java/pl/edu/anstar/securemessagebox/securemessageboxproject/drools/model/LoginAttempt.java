package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Fakt Drools reprezentujący pojedynczą próbę logowania.
 *
 * Wrzucany do KieSession przez LoginAttemptService przy każdej próbie logowania.
 * Silnik reguł analizuje:
 *   1. Czy przekroczono próg brute-force (>5 błędnych prób w 3 min) - HIGH
 *   2. O jakiej porze dnia nastąpiła próba:
 *      07:00–17:00 - brak alertu (godziny pracy)
 *      17:00–24:00 - LOW  (pracownik poza godzinami, ale dopuszczalne)
 *      00:00–07:00 - HIGH (nikt nie powinien być w systemie — blokada konta)
 *
 * Po odpaleniu reguł pole {@code actionRequired} wskazuje co zrobić:
 *   NONE         - brak akcji
 *   BLOCK        - zablokuj konto na 24h
 *   ALERT_LOW    - zapisz alert LOW, przepuść logowanie
 */
@Data
@NoArgsConstructor
public class LoginAttempt {

    /** ID użytkownika z bazy danych (app_user.id) */
    private Long userId;

    /** Nazwa użytkownika (do logów i opisu alertu) */
    private String username;

    /** true = hasło było błędne; false = logowanie się powiodło */
    private boolean failed;

    /** Dokładny czas próby logowania (LocalDateTime.now() przy wywołaniu) */
    private LocalDateTime attemptTime;

    /** Adres IP nadawcy (z HttpServletRequest.getRemoteAddr()) */
    private String ipAddress;

    /**
     * Liczba NIEUDANYCH prób logowania dla tego użytkownika
     * z ostatnich 3 minut (pobrana z bazy PRZED wrzuceniem faktu do Drools).
     * Drools nie odpytuje bazy — wszystkie dane muszą być w fakcie.
     */
    private int recentFailedAttempts;

    // ---- Pola wypełniane przez Drools (akcje reguł) ----

    /** Akcja wymagana po odpaleniu reguł: NONE | BLOCK | ALERT_LOW */
    private String actionRequired = "NONE";

    /** Opis alertu generowany przez regułę (trafia do security_alert.description) */
    private String alertDescription;

    /** Poziom alertu: LOW | MEDIUM | HIGH (null jeśli actionRequired=NONE) */
    private String alertSeverity;

    /** Typ alertu zgodny z CHECK constraint tabeli security_alert */
    private String alertType;

    /** Powód blokady konta — przekazywany do app_user.block_reason */
    private String blockReason;

    public LoginAttempt(Long userId, String username, boolean failed,
                        LocalDateTime attemptTime, String ipAddress,
                        int recentFailedAttempts) {
        this.userId = userId;
        this.username = username;
        this.failed = failed;
        this.attemptTime = attemptTime;
        this.ipAddress = ipAddress;
        this.recentFailedAttempts = recentFailedAttempts;
    }
}
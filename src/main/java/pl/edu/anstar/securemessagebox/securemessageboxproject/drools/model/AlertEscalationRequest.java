package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Fakt Drools używany do oceny eskalacji alertów użytkownika.
 *
 * Wrzucany do KieSession po każdym nowym alercie (LOW lub MEDIUM),
 * zawiera aktualne liczniki alertów z ostatnich 10 minut dla danego użytkownika.
 *
 * Reguły eskalacji:
 *   1. 3× LOW + 1× MEDIUM w ciągu 10 min → ESCALATION_AGGREGATED (HIGH) + blokada
 *   2. 5× LOW w ciągu 10 min              → ESCALATION_AGGREGATED (HIGH) + blokada
 *
 * Po odpaleniu reguły:
 *   shouldEscalate=true  → DroolsSecurityService blokuje konto i unieważnia sesje
 *   shouldEscalate=false → brak akcji
 */
@Data
@NoArgsConstructor
public class AlertEscalationRequest {

    /** ID użytkownika (app_user.id) */
    private Long userId;

    /** Nazwa użytkownika (do logów i opisów alertów) */
    private String username;

    /**
     * Liczba alertów LOW dla tego użytkownika z ostatnich 10 minut.
     * Pobrana z bazy PRZED wrzuceniem faktu — Drools nie odpytuje bazy.
     */
    private int lowAlertsLast10Min;

    /**
     * Liczba alertów MEDIUM dla tego użytkownika z ostatnich 10 minut.
     * Pobrana z bazy PRZED wrzuceniem faktu — Drools nie odpytuje bazy.
     */
    private int mediumAlertsLast10Min;

    // ---- Pola wypełniane przez Drools ----

    /** true → konto powinno być zablokowane przez eskalację */
    private boolean shouldEscalate = false;

    /** Opis eskalacji zapisywany do tabeli security_alert */
    private String escalationDescription;

    /** Powód blokady konta (trafia do app_user.block_reason) */
    private String blockReason;

    public AlertEscalationRequest(Long userId, String username,
                                  int lowAlertsLast10Min, int mediumAlertsLast10Min) {
        this.userId = userId;
        this.username = username;
        this.lowAlertsLast10Min = lowAlertsLast10Min;
        this.mediumAlertsLast10Min = mediumAlertsLast10Min;
    }
}
package pl.edu.anstar.securemessagebox.securemessageboxproject.drools;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.AlertEscalationRequest;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.LoginAttempt;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.MessageScanRequest;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
public class ComprehensiveDroolsSecuritySystemTest {

    @Autowired
    private KieContainer kieContainer;

    private KieSession kieSession;

    @BeforeEach
    public void setUp() {
        // Czysta izolowana sesja Drools przed kazdym testem
        this.kieSession = kieContainer.newKieSession();
    }

    @AfterEach
    public void tearDown() {
        if (this.kieSession != null) {
            this.kieSession.dispose();
        }
    }

    // =========================================================================
    // SEKCJA 1: TESTY LOGOWANIA (BRUTE-FORCE & PORA DNIA)
    // =========================================================================

    @Test
    @DisplayName("Test Rule Brute Force Block")
    public void testBruteForceRule() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("adam_cyber");
        attempt.setFailed(true);
        attempt.setRecentFailedAttempts(6); // Wartosc powyzej progu 5 prob
        attempt.setIpAddress("192.168.1.50");
        attempt.setAttemptTime(LocalDateTime.now());
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        int fired = kieSession.fireAllRules();

        assertTrue(fired > 0, "Regula brute force powinna sie uruchomic");
        assertEquals("BLOCK", attempt.getActionRequired());
        assertEquals("HIGH", attempt.getAlertSeverity());
        assertEquals("BRUTE_FORCE", attempt.getAlertType());
        assertNotNull(attempt.getBlockReason());
    }

    @Test
    @DisplayName("Test Rule Login Evening Hours Low Alert")
    public void testLoginAfterHoursLow() {
        // Symulacja godziny 21:00 (wieczor)
        LocalDateTime eveningTime = LocalDateTime.now().withHour(21).withMinute(0);
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("pracownik_biura");
        attempt.setFailed(false);
        attempt.setIpAddress("10.0.0.5");
        attempt.setAttemptTime(eveningTime);
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        kieSession.fireAllRules();

        assertEquals("ALERT_LOW", attempt.getActionRequired());
        assertEquals("LOW", attempt.getAlertSeverity());
        assertEquals("LOGIN_AFTER_HOURS_LOW", attempt.getAlertType());
    }

    @Test
    @DisplayName("Test Rule Login Night Hours High Block")
    public void testLoginAfterHoursHigh() {
        // Symulacja godziny 02:00 w nocy
        LocalDateTime nightTime = LocalDateTime.now().withHour(2).withMinute(0);
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("nocny_intruz");
        attempt.setFailed(false);
        attempt.setIpAddress("185.23.4.12");
        attempt.setAttemptTime(nightTime);
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        kieSession.fireAllRules();

        assertEquals("BLOCK", attempt.getActionRequired());
        assertEquals("HIGH", attempt.getAlertSeverity());
        assertEquals("LOGIN_AFTER_HOURS_HIGH", attempt.getAlertType());
        assertNotNull(attempt.getBlockReason());
    }

    // =========================================================================
    // SEKCJA 2: TESTY OCHRONY PRZED WYCIEKIEM DANYCH (DLP)
    // =========================================================================

    @Test
    @DisplayName("Test DLP Pesel Detection Pattern")
    public void testDlpPeselPattern() {
        MessageScanRequest scan = new MessageScanRequest();
        scan.setSenderId(10L);
        scan.setSenderUsername("sender1");
        scan.setReceiverId(11L);
        // Zawiera ciag tekstowy ze slowem kluczowym wyzwalanym przez reguly dlp
        scan.setPlainTextContent("Moj numer identyfikacyjny to zawierajacy pesel tekst.");
        scan.setBlocked(false);

        kieSession.insert(scan);
        kieSession.fireAllRules();

        assertTrue(scan.isBlocked(), "Wiadomosc powinna zostac zablokowana przez dlp");
        assertNotNull(scan.getBlockReason());
    }

    @Test
    @DisplayName("Test DLP Sensitive Keyword Detection")
    public void testDlpSensitiveKeywords() {
        MessageScanRequest scan = new MessageScanRequest();
        scan.setSenderId(10L);
        scan.setSenderUsername("sender1");
        scan.setReceiverId(11L);
        scan.setPlainTextContent("Tajne dane logowania: moje haslo do systemu.");
        scan.setBlocked(false);

        kieSession.insert(scan);
        kieSession.fireAllRules();

        assertTrue(scan.isBlocked(), "Wiadomosc zawierajaca slowo kluczowe powinna byc zablokowana");
    }

    // =========================================================================
    // SEKCJA 3: TESTY AUTOMATYCZNEJ ESKALACJI ALERTÓW
    // =========================================================================

    @Test
    @DisplayName("Test Escalation Rule 5x LOW to HIGH")
    public void testEscalation5xLowAlerts() {
        AlertEscalationRequest escalation = new AlertEscalationRequest();
        escalation.setUsername("test_user_low");
        escalation.setShouldEscalate(false);
        escalation.setLowAlertsLast10Min(5); // Próg wyzwalający regułę eskalacji LOW
        escalation.setMediumAlertsLast10Min(0);

        kieSession.insert(escalation);
        kieSession.fireAllRules();

        assertTrue(escalation.isShouldEscalate(), "Flaga eskalacji powinna zostac podniesiona dla 5xLOW");
        assertNotNull(escalation.getEscalationDescription());
        assertNotNull(escalation.getBlockReason());
    }

    @Test
    @DisplayName("Test Escalation Rule 3x MEDIUM to HIGH")
    public void testEscalation3xMediumAlerts() {
        AlertEscalationRequest escalation = new AlertEscalationRequest();
        escalation.setUsername("test_user_medium");
        escalation.setShouldEscalate(false);
        escalation.setLowAlertsLast10Min(0);
        escalation.setMediumAlertsLast10Min(3); // Próg wyzwalający regułę eskalacji MEDIUM

        kieSession.insert(escalation);
        kieSession.fireAllRules();

        assertTrue(escalation.isShouldEscalate(), "Flaga eskalacji powinna zostac podniesiona dla 3xMEDIUM");
        assertNotNull(escalation.getEscalationDescription());
        assertNotNull(escalation.getBlockReason());
    }
}
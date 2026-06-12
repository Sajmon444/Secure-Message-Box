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
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.LoginAttempt;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.MessageScanRequest;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
public class DroolsSecurityRulesTest {

    @Autowired
    private KieContainer kieContainer;

    private KieSession kieSession;

    @BeforeEach
    public void setUp() {
        this.kieSession = kieContainer.newKieSession();
    }

    @AfterEach
    public void tearDown() {
        if (this.kieSession != null) {
            this.kieSession.dispose();
        }
    }

    @Test
    @DisplayName("Brute Force Block Account Test")
    public void testBruteForceShouldBlockAccount() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("testUser");
        attempt.setFailed(true);
        attempt.setRecentFailedAttempts(6);
        attempt.setIpAddress("192.168.1.50");
        attempt.setAttemptTime(LocalDateTime.now());
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        int firedRules = kieSession.fireAllRules();

        assertTrue(firedRules > 0);
        assertEquals("BLOCK", attempt.getActionRequired());
        assertEquals("HIGH", attempt.getAlertSeverity());
        assertEquals("BRUTE_FORCE", attempt.getAlertType());
        assertNotNull(attempt.getBlockReason());
        assertTrue(attempt.getBlockReason().contains("BRUTE_FORCE"));
    }

    @Test
    @DisplayName("Brute Force Normal Attempts Test")
    public void testBruteForceShouldNotBlock() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("testUser");
        attempt.setFailed(true);
        attempt.setRecentFailedAttempts(5);
        attempt.setIpAddress("192.168.1.50");
        attempt.setAttemptTime(LocalDateTime.now());
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        int firedRules = kieSession.fireAllRules();

        assertEquals(0, firedRules);
        assertEquals("NONE", attempt.getActionRequired());
    }

    @Test
    @DisplayName("Session Working Hours Test")
    public void testSessionWorkingHoursNoAlert() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("user1");
        attempt.setFailed(false);
        attempt.setIpAddress("10.0.0.5");
        attempt.setAttemptTime(LocalDateTime.now().withHour(12).withMinute(0));
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        int firedRules = kieSession.fireAllRules();

        assertEquals(0, firedRules);
        assertEquals("NONE", attempt.getActionRequired());
    }

    @Test
    @DisplayName("Session Evening Hours Test")
    public void testSessionEveningHoursAlertLow() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("user2");
        attempt.setFailed(false);
        attempt.setIpAddress("10.0.0.5");
        attempt.setAttemptTime(LocalDateTime.now().withHour(19).withMinute(30));
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        int firedRules = kieSession.fireAllRules();

        assertTrue(firedRules > 0);
        assertEquals("ALERT_LOW", attempt.getActionRequired());
        assertEquals("LOW", attempt.getAlertSeverity());
        assertEquals("LOGIN_AFTER_HOURS_LOW", attempt.getAlertType());
    }

    @Test
    @DisplayName("Session Night Hours Test")
    public void testSessionNightHoursBlockHigh() {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername("user3");
        attempt.setFailed(false);
        attempt.setIpAddress("185.23.4.12");
        attempt.setAttemptTime(LocalDateTime.now().withHour(2).withMinute(15));
        attempt.setActionRequired("NONE");

        kieSession.insert(attempt);
        int firedRules = kieSession.fireAllRules();

        assertTrue(firedRules > 0);
        assertEquals("BLOCK", attempt.getActionRequired());
        assertEquals("HIGH", attempt.getAlertSeverity());
        assertEquals("LOGIN_AFTER_HOURS_HIGH", attempt.getAlertType());
        assertNotNull(attempt.getBlockReason());
    }

    @Test
    @DisplayName("DLP Keyword Detected Test")
    public void testDlpKeywordsShouldBlock() {
        MessageScanRequest request = new MessageScanRequest();
        request.setSenderId(1L);
        request.setSenderUsername("sender");
        request.setReceiverId(2L);
        request.setPlainTextContent("My pesel number is 99121200000.");
        request.setBlocked(false);

        kieSession.insert(request);
        int firedRules = kieSession.fireAllRules();

        assertTrue(firedRules > 0);
        assertTrue(request.isBlocked());
        assertEquals("DLP_SENSITIVE_KEYWORD", request.getAlertType());
        assertNotNull(request.getBlockReason());
    }

    @Test
    @DisplayName("DLP Safe Message Pass Test")
    public void testDlpSafeMessageShouldPass() {
        MessageScanRequest request = new MessageScanRequest();
        request.setSenderId(1L);
        request.setSenderUsername("sender");
        request.setReceiverId(2L);
        request.setPlainTextContent("Hello, how are you today?");
        request.setBlocked(false);

        kieSession.insert(request);
        int firedRules = kieSession.fireAllRules();

        assertEquals(0, firedRules);
        assertFalse(request.isBlocked());
    }
}
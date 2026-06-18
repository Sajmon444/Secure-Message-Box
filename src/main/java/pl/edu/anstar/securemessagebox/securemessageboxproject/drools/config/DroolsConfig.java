package pl.edu.anstar.securemessagebox.securemessageboxproject.drools.config;

import org.kie.api.KieServices;
import org.kie.api.builder.KieBuilder;
import org.kie.api.builder.KieFileSystem;
import org.kie.api.builder.KieModule;
import org.kie.api.runtime.KieContainer;
import org.kie.internal.io.ResourceFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Konfiguracja silnika Drools.
 *
 * Ładuje zestaw zmodularyzowanych plików reguł z zasobów aplikacji:
 * 1. rules/test-rule.drl        - testowy fakt DroolsTestFact (weryfikacja startu)
 * 2. rules/brute-force-rules.drl - detekcja ataków brute-force (blokowanie kont)
 * 3. rules/session-rules.drl     - dynamiczna ocena ryzyka sesji na podstawie pory dnia
 * 4. rules/dlp-rules.drl         - Data Loss Prevention (skanowanie wiadomości STANDARD)
 * 5. rules/escalation-rules.drl  - agregacja i automatyczna eskalacja alertów niskiego ryzyka
 *
 * Silnik Drools kompiluje wszystkie pliki współdzielące ten sam pakiet w jedną,
 * spójną bazę wiedzy. Priorytety (salience) działają globalnie pomiędzy plikami.
 *
 * KieContainer jest Springowym singletonem — jedna instancja na całą aplikację.
 * KieSession jest tworzony per-request w DroolsSecurityService (i zawsze dispose()'owany).
 */
@Configuration
public class DroolsConfig {

    @Bean
    public KieContainer kieContainer() {
        KieServices kieServices = KieServices.Factory.get();
        KieFileSystem kieFileSystem = kieServices.newKieFileSystem();

        // Ładowanie zmodularyzowanych plików reguł bezpieczeństwa
        kieFileSystem.write(ResourceFactory.newClassPathResource("rules/test-rule.drl"));
        kieFileSystem.write(ResourceFactory.newClassPathResource("rules/brute-force-rules.drl"));
        kieFileSystem.write(ResourceFactory.newClassPathResource("rules/session-rules.drl"));
        kieFileSystem.write(ResourceFactory.newClassPathResource("rules/dlp-rules.drl"));
        kieFileSystem.write(ResourceFactory.newClassPathResource("rules/escalation-rules.drl"));

        KieBuilder kieBuilder = kieServices.newKieBuilder(kieFileSystem);
        kieBuilder.buildAll();

        if (kieBuilder.getResults().hasMessages(org.kie.api.builder.Message.Level.ERROR)) {
            throw new IllegalStateException(
                    "Błąd kompilacji reguł Drools: " + kieBuilder.getResults().toString()
            );
        }

        KieModule kieModule = kieBuilder.getKieModule();
        return kieServices.newKieContainer(kieModule.getReleaseId());
    }
}
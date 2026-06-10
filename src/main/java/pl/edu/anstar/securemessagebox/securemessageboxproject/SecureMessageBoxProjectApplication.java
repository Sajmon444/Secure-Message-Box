package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;
import pl.edu.anstar.securemessagebox.securemessageboxproject.drools.model.DroolsTestFact; // Nowy import
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecureMessageBoxProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureMessageBoxProjectApplication.class, args);
    }

    @Bean
    public CommandLineRunner testDrools(KieContainer kieContainer) {
        return args -> {
            System.out.println(">>> Inicjalizacja testu silnika Drools w nowej strukturze... <<<");

            KieSession kieSession = kieContainer.newKieSession();
            DroolsTestFact testFact = new DroolsTestFact("URUCHOM");

            kieSession.insert(testFact);
            int firedRulesCount = kieSession.fireAllRules();
            kieSession.dispose();

            System.out.println(">>> Liczba uruchomionych reguł: " + firedRulesCount);
            if (testFact.isDroolsIsWorking() && firedRulesCount > 0) {
                System.out.println(">>> SUKCES: Drools działa poprawnie w wydzielonym pakiecie! <<<");
            } else {
                System.out.println(">>> BŁĄD: Reguła nie zadziałała. Sprawdź ścieżki pakietów. <<<");
            }
        };
    }
}
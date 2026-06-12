package pl.edu.anstar.securemessagebox.securemessageboxproject;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Kontroler autoryzacji.
 *
 * Obsługuje:
 * - logowanie użytkowników,
 * - rejestrację użytkowników,
 * - wyświetlanie dashboardu.
 *
 * Komunikaty błędów logowania są budowane na podstawie
 * wyjątków zapisanych przez Spring Security w sesji.
 * Dzięki temu można wyświetlać różne komunikaty
 * (np. błędne hasło lub zablokowane konto)
 * bez używania dodatkowych parametrów URL.
 */
@Controller
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/login")
    public String showLoginForm(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "locked", required = false) Boolean locked,
            Model model) {

        // Przypadek 1: Adres to /login?locked=true
        if (locked != null && locked) {
            model.addAttribute("errorMessage", "Konto zostało zablokowane ze względów bezpieczeństwa. Spróbuj ponownie później.");
        }
        // Przypadek 2: Adres to /login?error (standardowy błędny login/hasło)
        else if (error != null) {
            model.addAttribute("errorMessage", "Nieprawidłowa nazwa użytkownika lub hasło.");
        }

        // Jeśli żaden parametr nie występuje, errorMessage nie zostanie dodany,
        // a użytkownik zobaczy czysty formularz logowania.

        return "login";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String registerSubmit(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam("e2eePassword") String e2eePassword,
            Model model) {

        try {
            String kdfSalt = authService.register(username, password, e2eePassword);

            if (kdfSalt == null) {
                model.addAttribute("errorMsg", "Nazwa użytkownika jest już zajęta.");
                return "register";
            }

            model.addAttribute("username", username);
            model.addAttribute("kdfSalt", kdfSalt);

            return "private-key";

        } catch (Exception e) {
            log.error("Błąd rejestracji", e);
            model.addAttribute("errorMsg", "Błąd serwera: " + e.getMessage());
            return "register";
        }
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        model.addAttribute("username", userDetails.getUsername());
        return "dashboard";
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }
}
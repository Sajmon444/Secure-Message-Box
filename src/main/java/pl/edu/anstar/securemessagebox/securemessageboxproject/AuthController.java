package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Kontroler widoków — obsługuje ekrany logowania, rejestracji i dashboardu.
 * Używa Thymeleaf do renderowania stron HTML.
 */
@Controller
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ----------------------------------------------------------------
    // EKRAN LOGOWANIA
    // ----------------------------------------------------------------

    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            Model model) {

        if (error != null) {
            model.addAttribute("errorMsg", "Nieprawidłowa nazwa użytkownika lub hasło.");
        }
        if (logout != null) {
            model.addAttribute("logoutMsg", "Zostałeś wylogowany.");
        }
        return "login"; // src/main/resources/templates/login.html
    }

    // ----------------------------------------------------------------
    // EKRAN REJESTRACJI
    // ----------------------------------------------------------------

    @GetMapping("/register")
    public String registerPage() {
        return "register"; // src/main/resources/templates/register.html
    }

    @PostMapping("/register")
    public String registerSubmit(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            Model model) {

        boolean success = authService.register(username, password);

        if (success) {
            return "redirect:/login?registered=true";
        } else {
            model.addAttribute("errorMsg", "Nazwa użytkownika jest już zajęta.");
            return "register";
        }
    }

    // ----------------------------------------------------------------
    // EKRAN PO ZALOGOWANIU (testowy)
    // ----------------------------------------------------------------

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        model.addAttribute("username", userDetails.getUsername());
        return "dashboard"; // src/main/resources/templates/dashboard.html
    }

    // ----------------------------------------------------------------
    // PRZEKIEROWANIE Z /
    // ----------------------------------------------------------------

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }
}

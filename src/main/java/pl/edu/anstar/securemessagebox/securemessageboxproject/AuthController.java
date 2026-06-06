package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

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
            Model model) {

        log.info("Próba rejestracji użytkownika: {}", username);
        try {
            boolean success = authService.register(username, password);
            if (success) {
                log.info("Rejestracja zakończona sukcesem dla: {}", username);
                return "redirect:/login?registered=true";
            } else {
                log.warn("Rejestracja nieudana – nazwa zajęta: {}", username);
                model.addAttribute("errorMsg", "Nazwa użytkownika jest już zajęta.");
                return "register";
            }
        } catch (Exception e) {
            log.error("Błąd podczas rejestracji użytkownika: {}", username, e);
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
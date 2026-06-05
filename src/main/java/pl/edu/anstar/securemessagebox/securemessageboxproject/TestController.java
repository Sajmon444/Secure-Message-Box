package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/")
    public String welcome() {
        return "<h1>Serwer działa poprawnie! 🚀</h1><p>Projekt Secure Message Box wstał bez błędów, a baza danych PostgreSQL i Spring Security są gotowe.</p>";
    }
}
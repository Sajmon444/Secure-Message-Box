package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handler obsługujący nieudane próby logowania w celu przekierowania użytkownika
 * na odpowiedni widok błędu.
 */
@Component
public class CustomAuthFailureHandler implements AuthenticationFailureHandler {

    /**
     * Przechwytuje wyjątki uwierzytelniania i realizuje przekierowania w zależności od typu błędu.
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        // Rozróżnienie między zablokowanym kontem a błędnymi danymi uwierzytelniającymi
        if (exception instanceof LockedException) {
            response.sendRedirect(request.getContextPath() + "/login?locked=true");
        } else {
            response.sendRedirect(request.getContextPath() + "/login?error=true");
        }
    }
}
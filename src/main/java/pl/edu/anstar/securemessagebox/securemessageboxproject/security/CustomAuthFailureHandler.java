package pl.edu.anstar.securemessagebox.securemessageboxproject.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        if (exception instanceof LockedException) {
            response.sendRedirect(request.getContextPath() + "/login?locked=true"); // Konto zablokowane
        } else {
            response.sendRedirect(request.getContextPath() + "/login?error=true"); // Złe hasło/login
        }
    }
}
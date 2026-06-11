package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * Konfiguracja Spring Security.
 *
 * Zmiany względem oryginału:
 *   1. Dodano SessionRegistry (Bean) — używany przez DroolsSecurityService
 *      do unieważniania sesji przy blokadzie konta.
 *   2. Włączono SessionManagement z maksymalnie 1 sesją per użytkownik.
 *   3. Dodano obsługę LockedException — /login?locked=true
 *   4. Dodano HttpSessionEventPublisher — wymagany przez SessionRegistry.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AppUserDetailsService appUserDetailsService;

    public SecurityConfig(AppUserDetailsService appUserDetailsService) {
        this.appUserDetailsService = appUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(appUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * SessionRegistry — rejestr aktywnych sesji Spring Security.
     * Wstrzykiwany do DroolsSecurityService w celu wymuszenia wylogowania
     * przy blokadzie konta (expireNow()).
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * Wymagany przez SessionRegistry — publikuje zdarzenia cyklu życia sesji HTTP
     * (tworzenie i niszczenie) do ApplicationContext.
     * Bez tego SessionRegistry nie będzie wiedział o zniszczonych sesjach.
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(sessionRegistry());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/register", "/").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .defaultSuccessUrl("/dashboard", true)
                        // Przekierowanie przy błędzie logowania (złe hasło lub konto zablokowane)
                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .permitAll()
                )
                // Zarządzanie sesjami — wymagane dla SessionRegistry
                .sessionManagement(session -> session
                        .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                        // Maksymalnie 1 aktywna sesja per użytkownik.
                        // expiredUrl — przekierowanie gdy sesja wygasła przez Drools (blokada)
                        .maximumSessions(1)
                        .sessionRegistry(sessionRegistry())
                        .expiredUrl("/login?expired=true")
                );

        return http.build();
    }
}
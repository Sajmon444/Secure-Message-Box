package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.edu.anstar.securemessagebox.securemessageboxproject.entity.AppUser;
import pl.edu.anstar.securemessagebox.securemessageboxproject.repository.AppUserRepository;

@Service
public class AuthService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public boolean register(String username, String rawPassword) {
        if (appUserRepository.existsByUsername(username)) {
            return false;
        }

        AppUser newUser = new AppUser();
        newUser.setUsername(username);
        newUser.setPasswordHash(passwordEncoder.encode(rawPassword));

        appUserRepository.saveAndFlush(newUser); // flush wymusza natychmiastowy INSERT do bazy
        return true;
    }
}
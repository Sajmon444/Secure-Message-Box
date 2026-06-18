package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
 * Kontroler obsługujący żądania związane z wysyłaniem, odbieraniem oraz deszyfrowaniem wiadomości.
 */
@Controller
@RequestMapping("/messages")
public class MessageController {

    private static final Logger log = LoggerFactory.getLogger(MessageController.class);
    private final MessageService messageService;

    public MessageController(MessageService messageService) {
        this.messageService = messageService;
    }

    /**
     * Wyświetlenie formularza wysyłania wiadomości.
     */
    @GetMapping("/send")
    public String sendPage(@AuthenticationPrincipal UserDetails user) {
        if (user == null) return "redirect:/login";
        return "send";
    }

    /**
     * Przetworzenie formularza wysyłki wiadomości.
     */
    @PostMapping("/send")
    public String sendSubmit(@AuthenticationPrincipal UserDetails user,
                             @RequestParam("receiverUsername") String receiverUsername,
                             @RequestParam("category")         String category,
                             @RequestParam("content")          String content,
                             @RequestParam(value = "msgPassword",  required = false, defaultValue = "") String msgPassword,
                             @RequestParam(value = "e2eePassword", required = false, defaultValue = "") String e2eePassword,
                             Model model) {

        if (user == null) return "redirect:/login";

        try {
            messageService.sendMessage(
                    user.getUsername(), receiverUsername, category,
                    content, msgPassword, e2eePassword);
            model.addAttribute("successMsg", "Wiadomość wysłana pomyślnie!");
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMsg", e.getMessage());
        } catch (Exception e) {
            log.error("Błąd wysyłania wiadomości", e);
            model.addAttribute("errorMsg", "Błąd: " + e.getMessage());
        }
        return "send";
    }

    /**
     * Pobranie i wyświetlenie skrzynki odbiorczej zalogowanego użytkownika.
     */
    @GetMapping("/inbox")
    public String inboxPage(@AuthenticationPrincipal UserDetails user, Model model) {
        if (user == null) return "redirect:/login";
        model.addAttribute("messages", messageService.getInbox(user.getUsername()));
        return "inbox";
    }

    /**
     * Wykonanie procesu deszyfrowania wybranej wiadomości.
     */
    @PostMapping("/decrypt/{id}")
    public String decrypt(@PathVariable("id") Long id,
                          @RequestParam("msgPassword") String msgPassword,
                          @AuthenticationPrincipal UserDetails user,
                          Model model) {
        if (user == null) return "redirect:/login";
        try {
            MessageService.DecryptResult result = messageService.decryptMessage(id, msgPassword);
            model.addAttribute("decryptedId",     id);
            model.addAttribute("decryptedText",   result.plainText());
            model.addAttribute("signaturePresent", result.signaturePresent());
            model.addAttribute("signatureValid",   result.signatureValid());
        } catch (SecurityException e) {
            model.addAttribute("decryptErrorId", id);
            model.addAttribute("decryptError", "⚠️ " + e.getMessage());
        } catch (Exception e) {
            model.addAttribute("decryptErrorId", id);
            model.addAttribute("decryptError", "Złe hasło E2EE lub błąd odszyfrowania.");
        }
        model.addAttribute("messages", messageService.getInbox(user.getUsername()));
        return "inbox";
    }
}
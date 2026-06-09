package pl.edu.anstar.securemessagebox.securemessageboxproject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/messages")
public class MessageController {

    private static final Logger log = LoggerFactory.getLogger(MessageController.class);
    private final MessageService messageService;

    public MessageController(MessageService messageService) {
        this.messageService = messageService;
    }

    @GetMapping("/send")
    public String sendPage(@AuthenticationPrincipal UserDetails user) {
        if (user == null) return "redirect:/login";
        return "send";
    }

    @PostMapping("/send")
    public String sendSubmit(@AuthenticationPrincipal UserDetails user,
                             @RequestParam("receiverUsername") String receiverUsername,
                             @RequestParam("category")         String category,
                             @RequestParam("content")          String content,
                             // Hasło dla kategorii STANDARD (AES)
                             @RequestParam(value = "msgPassword",  required = false, defaultValue = "") String msgPassword,
                             // Hasło E2EE — INNE niż hasło logowania, tylko dla E2EE
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

    @GetMapping("/inbox")
    public String inboxPage(@AuthenticationPrincipal UserDetails user, Model model) {
        if (user == null) return "redirect:/login";
        model.addAttribute("messages", messageService.getInbox(user.getUsername()));
        return "inbox";
    }

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
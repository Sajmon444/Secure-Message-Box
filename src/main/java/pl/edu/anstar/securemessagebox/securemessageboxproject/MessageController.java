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

    // ----------------------------------------------------------------
    // WYŚLIJ WIADOMOŚĆ — GET (formularz)
    // ----------------------------------------------------------------

    @GetMapping("/send")
    public String sendPage(@AuthenticationPrincipal UserDetails user, Model model) {
        model.addAttribute("users", messageService.getAllUsers());
        model.addAttribute("currentUser", user.getUsername());
        return "send";
    }

    // ----------------------------------------------------------------
    // WYŚLIJ WIADOMOŚĆ — POST (obsługa formularza)
    // ----------------------------------------------------------------

    @PostMapping("/send")
    public String sendSubmit(@AuthenticationPrincipal UserDetails user,
                             @RequestParam("receiverId") Long receiverId,
                             @RequestParam("category") String category,
                             @RequestParam("content") String content,
                             @RequestParam("msgPassword") String msgPassword,
                             Model model) {
        try {
            messageService.sendMessage(user.getUsername(), receiverId, category, content, msgPassword);
            model.addAttribute("successMsg", "Wiadomość wysłana!");
        } catch (Exception e) {
            log.error("Błąd wysyłania wiadomości", e);
            model.addAttribute("errorMsg", "Błąd: " + e.getMessage());
        }
        model.addAttribute("users", messageService.getAllUsers());
        model.addAttribute("currentUser", user.getUsername());
        return "send";
    }

    // ----------------------------------------------------------------
    // SKRZYNKA ODBIORCZA — GET
    // ----------------------------------------------------------------

    @GetMapping("/inbox")
    public String inboxPage(@AuthenticationPrincipal UserDetails user, Model model) {
        model.addAttribute("messages", messageService.getInbox(user.getUsername()));
        return "inbox";
    }

    // ----------------------------------------------------------------
    // ODSZYFRUJ WIADOMOŚĆ — POST (Ajax-free, zwykły formularz)
    // ----------------------------------------------------------------

    @PostMapping("/decrypt/{id}")
    public String decrypt(@PathVariable("id") Long id,
                          @RequestParam("msgPassword") String msgPassword,
                          @AuthenticationPrincipal UserDetails user,
                          Model model) {
        try {
            String plainText = messageService.decryptMessage(id, msgPassword);
            model.addAttribute("decryptedId", id);
            model.addAttribute("decryptedText", plainText);
        } catch (Exception e) {
            model.addAttribute("decryptErrorId", id);
            model.addAttribute("decryptError", "Złe hasło lub błąd odszyfrowania.");
        }
        model.addAttribute("messages", messageService.getInbox(user.getUsername()));
        return "inbox";
    }
}
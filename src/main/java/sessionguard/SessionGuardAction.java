package sessionguard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Toolkit;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Session Handling Action to provide 100% test case retention (Strict Mode).
 * When invoked by Burp's "Check session is valid" rule, this action pauses
 * the gate. Burp natively waits for this action to return before re-issuing
 * the modified request, guaranteeing zero test cases are lost.
 */
public class SessionGuardAction implements SessionHandlingAction {

    private final MontoyaApi api;
    private final GateController gate;
    private final SessionGuardTab tab;

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SessionGuardAction(MontoyaApi api, GateController gate, SessionGuardTab tab) {
        this.api = api;
        this.gate = gate;
        this.tab = tab;
    }

    @Override
    public String name() {
        return "Session Guard — Pause & Retry";
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        String url = actionData.request().url();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);

        // pause() returns true only for the first thread that triggers the pause
        if (gate.pause()) {
            // 1. Log to Session Guard tab
            String logMessage = String.format("[%s]  STRICT TRIGGER (Action)  ←  %s", timestamp, url);
            tab.addLogEntry(logMessage);
            tab.updateStatus(true);

            // 2. Raise critical Burp alert
            String alertMessage = String.format(
                    "SESSION EXPIRED (Strict Mode) — Trigger detected at %s. " +
                    "Scanner is PAUSED. Update your cookies/tokens, then click Resume in the Session Guard tab.",
                    url
            );
            api.logging().raiseCriticalEvent(alertMessage);
            api.logging().logToOutput("Session Guard: " + alertMessage);

            // 3. Popup notification + beep (on Swing EDT)
            if (tab.isPopupEnabled()) {
                SwingUtilities.invokeLater(() -> {
                    Toolkit.getDefaultToolkit().beep();
                    JOptionPane.showMessageDialog(
                            null,
                            buildPopupMessage(url),
                            "Session Guard — Session Expired!",
                            JOptionPane.WARNING_MESSAGE
                    );
                });
            }

            // 4. Sound alert even if popup is disabled
            if (tab.isSoundEnabled() && !tab.isPopupEnabled()) {
                Toolkit.getDefaultToolkit().beep();
            }
        } else {
            // Already paused, just block this thread until resumed.
            // Log silently so the user knows multiple threads were intercepted.
            String logMessage = String.format("[%s]  STRICT HELD (Action)  ←  %s", timestamp, url);
            tab.addLogEntry(logMessage);
        }

        // Block this thread. Burp will wait for us to return.
        try {
            gate.awaitIfPaused();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            api.logging().logToError("Session Guard: strict mode thread interrupted");
        }

        // Return the request unmodified to Burp.
        // Burp's native Session Handling Rule engine will handle updating the
        // request with the new cookie from the Cookie Jar and re-issuing it!
        return ActionResult.actionResult(actionData.request());
    }

    /**
     * Build a human-readable popup message for the strict mode session-expiry alert.
     */
    private String buildPopupMessage(String url) {
        return String.format(
                "⚠  Session Expired (Strict Mode)!\n\n" +
                "Burp Session Handling Rule intercepted a request to:\n%s\n\n" +
                "All scanner threads hitting this rule have been PAUSED.\n\n" +
                "To continue:\n" +
                "  1. Update your cookies / tokens in Burp's Cookie Jar\n" +
                "  2. Go to the \"Session Guard\" tab\n" +
                "  3. Click  ▶ Resume  to release the held requests\n\n" +
                "Burp will automatically re-issue the failed requests with updated cookies.",
                url
        );
    }
}

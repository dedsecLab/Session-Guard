package sessionguard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Toolkit;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.regex.Pattern;

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

        // Validation probe — confirm the session is truly expired before pausing.
        // This prevents false positives from scanner checks (e.g., Web Cache Deception)
        // that strip cookies and produce trigger-code responses.
        String validationUrl = tab.getValidationUrl();
        if (!validationUrl.isEmpty()) {
            boolean sessionStillValid = probeSessionValid(validationUrl, actionData);
            if (sessionStillValid) {
                String fpMsg = String.format(
                        "[%s]  ⏭ FALSE POSITIVE (Strict) — ignored (validation probe confirmed session is alive)  ←  %s",
                        timestamp, url
                );
                tab.addLogEntry(fpMsg);
                api.logging().logToOutput("Session Guard: " + fpMsg);
                // Return request unmodified — session is fine, let Burp proceed normally
                return ActionResult.actionResult(actionData.request());
            }
        }

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

    /**
     * Probe the validation URL to confirm session expiry.
     *
     * @return true if the session is still valid (trigger was a false positive),
     *         false if the session is expired (probe also triggered) or probe failed.
     */
    private boolean probeSessionValid(String validationUrl, SessionHandlingActionData actionData) {
        gate.setProbing(true);
        try {
            HttpRequest probeRequest = HttpRequest.httpRequestFromUrl(validationUrl);

            // Copy cookies from the original request to the validation probe
            String cookieValue = actionData.request().headerValue("Cookie");
            if (cookieValue != null) {
                probeRequest = probeRequest.withAddedHeader("Cookie", cookieValue);
            }

            api.logging().logToOutput("Session Guard: sending validation probe (Strict) → " + validationUrl);
            HttpRequestResponse probeResult = api.http().sendRequest(probeRequest);
            int probeStatus = probeResult.response().statusCode();

            // Check status code trigger
            Set<Integer> triggerCodes = tab.getTriggerStatusCodes();
            if (triggerCodes.contains(probeStatus)) {
                api.logging().logToOutput("Session Guard: probe confirmed EXPIRED (HTTP " + probeStatus + ")");
                return false;
            }

            // Check header regex
            String headerRegex = tab.getHeaderRegex();
            if (!headerRegex.isEmpty()) {
                try {
                    Pattern p = Pattern.compile(headerRegex, Pattern.CASE_INSENSITIVE);
                    StringBuilder headerStr = new StringBuilder();
                    probeResult.response().headers().forEach(h ->
                            headerStr.append(h.name()).append(": ").append(h.value()).append("\n"));
                    if (p.matcher(headerStr.toString()).find()) {
                        api.logging().logToOutput("Session Guard: probe confirmed EXPIRED (header regex match)");
                        return false;
                    }
                } catch (Exception ignored) {}
            }

            // Check body regex
            String bodyRegex = tab.getBodyRegex();
            if (!bodyRegex.isEmpty()) {
                try {
                    Pattern p = Pattern.compile(bodyRegex, Pattern.CASE_INSENSITIVE);
                    if (p.matcher(probeResult.response().bodyToString()).find()) {
                        api.logging().logToOutput("Session Guard: probe confirmed EXPIRED (body regex match)");
                        return false;
                    }
                } catch (Exception ignored) {}
            }

            // Probe returned a normal response — session is still alive
            api.logging().logToOutput("Session Guard: probe shows session VALID (HTTP " + probeStatus + ") — false positive");
            return true;

        } catch (Exception e) {
            api.logging().logToError("Session Guard: validation probe failed (Strict) — " + e.getMessage());
            return false; // fail-safe: assume session expired
        } finally {
            gate.setProbing(false);
        }
    }
}

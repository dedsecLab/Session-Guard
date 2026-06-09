package sessionguard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import java.awt.Toolkit;
import java.awt.Dimension;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Session Handling Action for Strict Mode (100% test case retention).
 *
 * Simple setup: just add "Invoke extension: Session Guard — Pause & Retry"
 * in your session handling rule. No macro needed.
 *
 * How it works:
 *   - Uses a smart cooldown-based validation probe (~1 probe every 30 seconds)
 *   - During cooldown: zero overhead, requests pass through instantly
 *   - When cooldown expires: probes the validation URL with cookie jar cookies
 *   - If session valid: resets cooldown, passes through
 *   - If session expired: pauses gate, notifies user, blocks ALL threads
 *   - After Resume: cooldown resets, immediately re-validates on next request
 *
 * Combined with HttpHandler response monitoring, this provides near-zero
 * leaked requests with minimal overhead.
 */
public class SessionGuardAction implements SessionHandlingAction {

    private final MontoyaApi api;
    private final GateController gate;
    private final SessionGuardTab tab;

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Only send a validation probe every 30 seconds (near-zero overhead)
    private static final long PROBE_COOLDOWN_MS = 30_000;
    private volatile long lastSuccessfulProbeMs = 0;

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
        // 1. If a probe is already in-flight, pass through to avoid recursion
        if (gate.isProbing()) {
            return ActionResult.actionResult(actionData.request());
        }

        // 2. If gate is already paused (by HttpHandler or previous probe), block immediately
        if (gate.isPaused()) {
            blockUntilResumed(actionData.request().url(), false);
            return ActionResult.actionResult(actionData.request());
        }

        // 3. No validation URL → can't probe, rely on HttpHandler response detection
        String validationUrl = tab.getValidationUrl();
        if (validationUrl.isEmpty()) {
            return ActionResult.actionResult(actionData.request());
        }

        // 4. Fast path: within cooldown → session was recently confirmed valid
        long now = System.currentTimeMillis();
        if (now - lastSuccessfulProbeMs < PROBE_COOLDOWN_MS) {
            return ActionResult.actionResult(actionData.request());
        }

        // 5. Cooldown expired → try to acquire the probe lock (only 1 thread probes)
        if (!gate.startProbing()) {
            // Another thread is already probing — pass through
            return ActionResult.actionResult(actionData.request());
        }

        boolean sessionExpired = false;
        try {
            // Double-check: gate might have been paused while waiting for CAS
            if (gate.isPaused()) {
                blockUntilResumed(actionData.request().url(), false);
                return ActionResult.actionResult(actionData.request());
            }

            // Double-check cooldown (another thread may have probed while we waited)
            long nowAfterCas = System.currentTimeMillis();
            if (nowAfterCas - lastSuccessfulProbeMs < PROBE_COOLDOWN_MS) {
                return ActionResult.actionResult(actionData.request());
            }

            // Send the validation probe
            sessionExpired = !probeSessionValid(validationUrl);
            if (!sessionExpired) {
                // Session is alive — reset cooldown
                lastSuccessfulProbeMs = System.currentTimeMillis();
                return ActionResult.actionResult(actionData.request());
            }
        } finally {
            gate.setProbing(false);
        }

        // 6. Session is EXPIRED — pause gate, notify, and block
        // Reset cooldown so after Resume, the very next request re-validates immediately
        lastSuccessfulProbeMs = 0;
        blockUntilResumed(actionData.request().url(), true);
        return ActionResult.actionResult(actionData.request());
    }

    /**
     * Block the current thread until the user clicks Resume.
     *
     * @param url           the URL of the request being held
     * @param firstDetector true if this thread is the one that detected the expiry
     */
    private void blockUntilResumed(String url, boolean firstDetector) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);

        if (firstDetector && gate.pause()) {
            // — This thread detected the expiry AND won the pause race —

            // 1. Log to Session Guard tab
            String logMessage = String.format("[%s]  STRICT TRIGGER (Action)  ←  %s", timestamp, url);
            tab.addLogEntry(logMessage);
            tab.updateStatus(true);

            // 2. Raise critical Burp alert
            String alertMessage = String.format(
                    "SESSION EXPIRED (Strict Mode) — Trigger detected at %s. " +
                    "Scanner is PAUSED. Update your cookies/tokens, then click Resume in the Session Guard tab.",
                    url);
            api.logging().raiseCriticalEvent(alertMessage);
            api.logging().logToOutput("Session Guard: " + alertMessage);

            // 3. Popup notification + beep
            if (tab.isPopupEnabled()) {
                SwingUtilities.invokeLater(() -> {
                    Toolkit.getDefaultToolkit().beep();
                    String messageText = buildPopupMessage(url);

                    JTextArea textArea = new JTextArea(messageText);
                    textArea.setEditable(false);
                    textArea.setLineWrap(true);
                    textArea.setWrapStyleWord(true);
                    textArea.setFont(new JLabel().getFont());
                    textArea.setOpaque(false);

                    JScrollPane scrollPane = new JScrollPane(textArea);
                    scrollPane.setBorder(null);
                    scrollPane.setOpaque(false);
                    scrollPane.getViewport().setOpaque(false);
                    scrollPane.setPreferredSize(new Dimension(550, 250));

                    JOptionPane.showMessageDialog(
                            null,
                            scrollPane,
                            "Session Guard — Session Expired!",
                            JOptionPane.WARNING_MESSAGE);
                });
            }

            // 4. Sound alert even if popup is disabled
            if (tab.isSoundEnabled() && !tab.isPopupEnabled()) {
                Toolkit.getDefaultToolkit().beep();
            }
        } else {
            // Already paused — just log
            String logMessage = String.format("[%s]  STRICT HELD (Action)  ←  %s", timestamp, url);
            tab.addLogEntry(logMessage);
        }

        // Block this thread until the user clicks Resume
        try {
            gate.awaitIfPaused();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            api.logging().logToError("Session Guard: strict mode thread interrupted");
        }
    }

    /**
     * Probe the validation URL to check if the session is still valid.
     *
     * @return true if session is still valid, false if expired
     */
    private boolean probeSessionValid(String validationUrl) {
        try {
            HttpRequest probeRequest = HttpRequest.httpRequestFromUrl(validationUrl);

            // Attach cookies from the Cookie Jar
            String cookieValue = getCookieHeaderFromJar(validationUrl);
            if (cookieValue != null && !cookieValue.isEmpty()) {
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
                    probeResult.response().headers()
                            .forEach(h -> headerStr.append(h.name()).append(": ").append(h.value()).append("\n"));
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
            api.logging().logToOutput("Session Guard: probe shows session VALID (HTTP " + probeStatus + ")");
            return true;

        } catch (Exception e) {
            api.logging().logToError("Session Guard: validation probe failed (Strict) — " + e.getMessage());
            return false; // fail-safe: assume session expired
        }
    }

    /**
     * Get cookies from Burp's Cookie Jar for the validation URL.
     */
    private String getCookieHeaderFromJar(String validationUrl) {
        try {
            java.net.URL url = new java.net.URL(validationUrl);
            String host = url.getHost().toLowerCase();
            String path = url.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }

            StringBuilder cookieHeader = new StringBuilder();
            for (burp.api.montoya.http.message.Cookie cookie : api.http().cookieJar().cookies()) {
                String domain = cookie.domain();
                if (domain == null) continue;
                domain = domain.toLowerCase();

                // Domain matching
                boolean domainMatch = false;
                if (domain.startsWith(".")) {
                    if (host.endsWith(domain.substring(1))) domainMatch = true;
                } else {
                    if (host.equals(domain) || host.endsWith("." + domain)) domainMatch = true;
                }
                if (!domainMatch) continue;

                // Path matching
                String cookiePath = cookie.path();
                if (cookiePath != null && !path.startsWith(cookiePath)) continue;

                if (cookieHeader.length() > 0) cookieHeader.append("; ");
                cookieHeader.append(cookie.name()).append("=").append(cookie.value());
            }
            return cookieHeader.toString();
        } catch (Exception e) {
            api.logging().logToError("Session Guard: error matching cookies for URL - " + e.getMessage());
            return "";
        }
    }

    /**
     * Build a human-readable popup message.
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
                url);
    }
}

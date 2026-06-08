package sessionguard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Toolkit;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Monitors HTTP responses for session-expiry status codes (e.g., 303).
 *
 * On detection:
 *   1. Closes the gate (blocks all future requests from monitored tools)
 *   2. Logs the event to the Session Guard tab
 *   3. Raises a critical Burp alert
 *   4. Shows a popup dialog + plays system beep
 *
 * On every outgoing request (monitored tools only):
 *   - Calls gate.awaitIfPaused() which blocks if session is expired
 *
 * Grace period:
 *   After resume, stale in-flight responses (from the resource pool) are
 *   silently ignored via gate.consumeGrace() to prevent false re-triggers.
 */
public class SessionGuardHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final GateController gate;
    private final SessionGuardTab tab;

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SessionGuardHttpHandler(MontoyaApi api, GateController gate, SessionGuardTab tab) {
        this.api = api;
        this.gate = gate;
        this.tab = tab;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // Only gate traffic from tools the user has enabled for monitoring
        if (tab.isToolMonitored(request.toolSource().toolType())) {
            try {
                gate.awaitIfPaused();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                api.logging().logToError("Session Guard: request thread interrupted while paused");
            }
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        // Skip validation probe responses to avoid recursive triggering
        if (gate.isProbing()) {
            return ResponseReceivedAction.continueWith(response);
        }

        // If the user has disabled the built-in detection (e.g. for Strict Mode), ignore responses.
        if (!tab.isPluginDetectionEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }

        // Only inspect responses from tools the user has enabled for monitoring
        if (!tab.isToolMonitored(response.toolSource().toolType())) {
            return ResponseReceivedAction.continueWith(response);
        }

        // Ignore responses if the initiating request had no cookies (e.g. Unauthenticated / WCD checks).
        // A request without cookies cannot have an "expired" session.
        boolean hasCookie = response.initiatingRequest().headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase("Cookie"));
        if (!hasCookie) {
            return ResponseReceivedAction.continueWith(response);
        }

        Set<Integer> triggerCodes = tab.getTriggerStatusCodes();
        int statusCode = response.statusCode();

        boolean triggered = false;
        
        // 1. Status Code Match
        if (triggerCodes.contains(statusCode)) {
            triggered = true;
        }

        // 2. Header Regex Match
        String headerRegex = tab.getHeaderRegex();
        if (!triggered && !headerRegex.isEmpty()) {
            try {
                Pattern p = Pattern.compile(headerRegex, Pattern.CASE_INSENSITIVE);
                StringBuilder headerStr = new StringBuilder();
                response.headers().forEach(h -> headerStr.append(h.name()).append(": ").append(h.value()).append("\n"));
                if (p.matcher(headerStr.toString()).find()) {
                    triggered = true;
                }
            } catch (Exception ignored) {}
        }

        // 3. Body Regex Match
        String bodyRegex = tab.getBodyRegex();
        if (!triggered && !bodyRegex.isEmpty()) {
            try {
                Pattern p = Pattern.compile(bodyRegex, Pattern.CASE_INSENSITIVE);
                if (p.matcher(response.bodyToString()).find()) {
                    triggered = true;
                }
            } catch (Exception ignored) {}
        }

        if (triggered && !gate.isPaused()) {
            // Check grace period — stale in-flight responses from before resume
            if (gate.consumeGrace()) {
                String url = response.initiatingRequest().url();
                String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);
                String graceMsg = String.format(
                        "[%s]  ⏭ GRACE — HTTP %d ignored (stale pipeline, %d grace left)  ←  %s",
                        timestamp, statusCode, gate.getGraceRemaining(), url
                );
                tab.addLogEntry(graceMsg);
                api.logging().logToOutput("Session Guard: " + graceMsg);
                return ResponseReceivedAction.continueWith(response);
            }

            // Validation probe — confirm the session is truly expired before pausing.
            // This prevents false positives from scanner checks (e.g., Web Cache Deception)
            // that strip cookies and produce trigger-code responses.
            String validationUrl = tab.getValidationUrl();
            if (!validationUrl.isEmpty()) {
                boolean sessionStillValid = probeSessionValid(validationUrl, response);
                if (sessionStillValid) {
                    String fpUrl = response.initiatingRequest().url();
                    String fpTs = LocalDateTime.now().format(TIMESTAMP_FMT);
                    String fpMsg = String.format(
                            "[%s]  ⏭ FALSE POSITIVE — HTTP %d ignored (validation probe confirmed session is alive)  ←  %s",
                            fpTs, statusCode, fpUrl
                    );
                    tab.addLogEntry(fpMsg);
                    api.logging().logToOutput("Session Guard: " + fpMsg);
                    return ResponseReceivedAction.continueWith(response);
                }
            }

            // No grace remaining and validation confirms expired — real session expiry
            String url = response.initiatingRequest().url();
            String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);

            // 1. Close the gate — all subsequent requests from monitored tools will block
            gate.pause();

            // 2. Log to Session Guard tab
            String logMessage = String.format("[%s]  TRIGGER (HTTP %d)  ←  %s", timestamp, statusCode, url);
            tab.addLogEntry(logMessage);
            tab.updateStatus(true);

            // 3. Raise critical Burp alert (appears in Alerts tab)
            String alertMessage = String.format(
                    "SESSION EXPIRED — Trigger detected at %s (HTTP %d). " +
                    "Scanner is PAUSED. Update your cookies/tokens, then click Resume in the Session Guard tab.",
                    url, statusCode
            );
            api.logging().raiseCriticalEvent(alertMessage);
            api.logging().logToOutput("Session Guard: " + alertMessage);

            // 4. Popup notification + system beep (on Swing EDT)
            if (tab.isPopupEnabled()) {
                SwingUtilities.invokeLater(() -> {
                    Toolkit.getDefaultToolkit().beep();
                    JOptionPane.showMessageDialog(
                            null,
                            buildPopupMessage(statusCode, url),
                            "Session Guard — Session Expired!",
                            JOptionPane.WARNING_MESSAGE
                    );
                });
            }

            // 5. Sound alert even if popup is disabled
            if (tab.isSoundEnabled() && !tab.isPopupEnabled()) {
                Toolkit.getDefaultToolkit().beep();
            }
        }

        return ResponseReceivedAction.continueWith(response);
    }

    /**
     * Probe the validation URL to confirm session expiry.
     *
     * @return true if the session is still valid (trigger was a false positive),
     *         false if the session is expired (probe also triggered) or probe failed.
     */
    private boolean probeSessionValid(String validationUrl, HttpResponseReceived originalResponse) {
        gate.setProbing(true);
        try {
            HttpRequest probeRequest = HttpRequest.httpRequestFromUrl(validationUrl);

            // Copy cookies from the initiating request to the validation probe
            String cookieValue = originalResponse.initiatingRequest().headerValue("Cookie");
            if (cookieValue != null) {
                probeRequest = probeRequest.withAddedHeader("Cookie", cookieValue);
            }

            api.logging().logToOutput("Session Guard: sending validation probe → " + validationUrl);
            HttpRequestResponse probeResult = api.http().sendRequest(probeRequest);
            int probeStatus = probeResult.response().statusCode();

            // Check if probe response matches any trigger condition
            Set<Integer> probeTriggerCodes = tab.getTriggerStatusCodes();
            if (probeTriggerCodes.contains(probeStatus)) {
                api.logging().logToOutput("Session Guard: probe confirmed EXPIRED (HTTP " + probeStatus + ")");
                return false;
            }

            // Check header regex against probe response
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

            // Check body regex against probe response
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
            api.logging().logToError("Session Guard: validation probe failed — " + e.getMessage());
            return false; // fail-safe: assume session expired
        } finally {
            gate.setProbing(false);
        }
    }

    /**
     * Build a human-readable popup message for the session-expiry alert.
     */
    private String buildPopupMessage(int statusCode, String url) {
        return String.format(
                "⚠  Session Expired!\n\n" +
                "Trigger response detected at:\n%s\n(HTTP %d)\n\n" +
                "All monitored tool requests have been PAUSED.\n\n" +
                "To continue:\n" +
                "  1. Update your cookies / tokens in Burp's Cookie Jar\n" +
                "  2. Update any custom headers if needed\n" +
                "  3. Go to the \"Session Guard\" tab\n" +
                "  4. Click  ▶ Resume  to continue scanning\n\n" +
                "Requests blocked so far: %d",
                url, statusCode, gate.getBlockedCount()
        );
    }
}

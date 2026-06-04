package sessionguard;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Session Guard — Burp Suite Extension
 *
 * Detects session expiry (HTTP 303 or configurable status codes) during scanning,
 * pauses all scanner/extension traffic, and alerts the user to update cookies/tokens.
 *
 * Architecture:
 *   SessionGuardExtension (entry point)
 *     ├── GateController         — thread-safe gate (CountDownLatch)
 *     ├── SessionGuardTab        — custom Burp tab (status, log, resume, config)
 *     └── SessionGuardHttpHandler — HttpHandler (detects expired sessions, gates requests)
 */
public class SessionGuardExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Session Guard");

        // Shared gate controller — connects the handler (pauses) with the tab (resumes)
        GateController gate = new GateController();

        // Custom tab UI — must be created before the handler so handler can log to it
        SessionGuardTab tab = new SessionGuardTab(api, gate);

        // HTTP handler — monitors responses and blocks requests when session expires (Plug-and-play mode)
        SessionGuardHttpHandler handler = new SessionGuardHttpHandler(api, gate, tab);

        // Session Handling Action — for 100% test case retention (Strict mode)
        SessionGuardAction action = new SessionGuardAction(api, gate, tab);

        // Register with Burp
        api.http().registerHttpHandler(handler);
        api.http().registerSessionHandlingAction(action);
        api.userInterface().registerSuiteTab("Session Guard", tab.getPanel());

        // Save settings when extension unloads or Burp closes
        api.extension().registerUnloadingHandler(tab::saveSettings);

        api.logging().logToOutput("═══════════════════════════════════════════════");
        api.logging().logToOutput("  Session Guard v1.0.0 loaded successfully");
        api.logging().logToOutput("  Mode 1: Plug-and-play (HttpHandler active)");
        api.logging().logToOutput("  Mode 2: Strict Mode (Session Handling Action registered)");
        api.logging().logToOutput("═══════════════════════════════════════════════");
    }
}

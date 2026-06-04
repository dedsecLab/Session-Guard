# Session Guard — Burp Suite Extension

A Burp Suite extension that **detects session/cookie expiry** during active scanning and **pauses all scanner traffic** until you update your credentials.

## The Problem

When cookies expire mid-scan, the target server returns HTTP redirects or error status codes (e.g., `303`, `401`, `403`). If you have a resource pool running concurrent requests (e.g., 10 concurrent requests), all in-flight requests will fail, and the scanner will continue queueing and firing hundreds of requests with stale tokens. This pollutes your scan logs and fails all test cases, forcing you to restart the entire scan from scratch.

## The Solution

Session Guard monitors HTTP traffic from your selected Burp Suite tools. When it detects any of your configured trigger status codes:

1. **Blocks Future Traffic Instantly**: Future requests are intercepted and held in a thread-safe gate (using `CountDownLatch` to sleep threads efficiently with zero CPU spin).
2. **Alerts You Immediately**: Triggers a popup alert dialog, plays an audible system beep, and writes a warning to the Burp Suite **Alerts** tab.
3. **Grace Period Protection**: Allows you to define a grace period (e.g., ignoring the next 10 stale responses after you click Resume) to clear out the in-flight pipeline and prevent immediate false re-triggers.
4. **Resumes Seamlessly**: Once you update your cookies/tokens in Burp's Cookie Jar or session headers, click **Resume Scanning** to release all queued requests.
5. **Project Persistence**: All your configured settings and detection logs are automatically saved and loaded directly from your Burp Suite project file.

---

## Operating Modes

| Feature | Mode 1: Plug-and-play (Default) | Mode 2: Strict Mode (Experimental) |
| :--- | :--- | :--- |
| **Setup Required** | None (Just install and scan) | Manual (Burp Session Handling Rules) |
| **Test Case Retention** | Loses a few in-flight test cases | **100% test cases retained** |
| **Retry Logic** | Fails in-flight requests | Automatically re-issues failed requests |
| **Ideal For** | Quick scans, easy setup | Deep, comprehensive audits |

---

### Mode 1: Plug-and-play (Default)

**Setup Instructions:**

1. Configure your scan target and start an active scan.
2. Session Guard runs silently in the background.
3. **Cookie expires** → Extension triggers based on your configured status codes or regex patterns:
   - Scanner freezes (future requests held in queue).
   - Popup alert appears, system beep plays, and Burp Alerts tab shows critical notification.
4. **You** update cookies, tokens, and headers as needed.
5. Switch to the **Session Guard** tab and click **▶ Resume**.
6. All held requests resume with the updated credentials. *(Note: Requests that were already in-flight before the pause will return your configured trigger codes and be ignored via the Grace Period).*

### Mode 2: Strict Mode (100% Test Case Retention) (Experimental)

**Setup Instructions:**
In Plug-and-play mode, the requests that were already sent over the network when the session expired will fail, and those test cases will be lost (false negatives). To guarantee zero lost test cases, use **Strict Mode** by configuring Burp's native Session Handling Rules to invoke Session Guard and automatically retry failed requests:

1. Go to **Settings** → **Sessions** → **Session Handling Rules**.
2. Click **Add** to create a new rule.
3. In **Rule Actions**, click **Add** → **Check session is valid**.
4. Configure the "Check session is valid" dialog to match your session expiry signature (e.g., HTTP 303 or regex).
5. Under "If session is invalid", select **Run a macro**.
   - *(Note: Burp Suite's UI requires a macro here. If you don't have a login macro, simply create a "Dummy Macro" that makes a single fast request, such as a GET to the homepage).*
6. Select your macro, and scroll to the bottom of the window.
7. **CRITICAL**: Check the boxes for **Update current request with cookies from session handling cookie jar** and **If session is invalid, perform the action, update the request, and reissue it**.
8. **CRITICAL**: Check the box for **After running the macro, invoke a Burp extension action handler** and select **Session Guard — Pause & Retry**.
9. In the **Scope** tab, ensure the rule applies to **Scanner** (or your desired tools) and the correct target URLs.

When this rule triggers, Session Guard will pause all threads hitting the rule. When you click **▶ Resume**, Burp will natively update the cookies and **re-issue all the failed test cases**!

---

## Functional Features

### 1. Trigger by Status Codes
You can specify multiple HTTP response status codes that will trigger a session pause.
* **How to use it**: Enter the codes into the **Trigger Status Codes** field in the Session Guard tab, separated by commas, spaces, or semicolons (e.g., `303,404,403` or `303 401 403`).
* **Under the Hood**: The input is parsed dynamically using the regular expression `[,;\s]+`. Invalid entries or letters are safely ignored, defaulting back to `303` if parsing fails.

### 2. Trigger by Regex Pattern (Header or Body)
In addition to status codes, you can detect session expiry by matching custom patterns in the HTTP response.
* **Header Match Regex**: Provide a regex pattern (e.g., `Location:.*login\.php`) to match against response headers.
* **Body Match Regex**: Provide a regex pattern (e.g., `Your session has expired`) to match against the response body.
* If either regex pattern matches, Session Guard will trigger immediately. All regex matches are evaluated case-insensitively.

### 3. Tailored Tool Monitoring
You can configure which Burp tools Session Guard monitors:
* **Scanner**: Monitors Burp's built-in active and passive scanners.
* **Extensions**: Monitors traffic sent by other extensions (such as *Active Scan++*, *Collaborator*, or custom scanner tools).
* **Intruder**: Monitors intruder attack requests.
* **Repeater**: Monitors repeater tab requests (disabled by default to prevent blocking manual tests).
* **Proxy**: Monitors proxy browser traffic (disabled by default to prevent browser hangs).

### 3. Grace Period (Stale Pipeline Drain)
If you have a resource pool of $N$ concurrent requests, $N-1$ requests might still be sent or in-flight immediately after the session expires. When you update the session cookie and resume scanning, those stale requests will eventually return the trigger status code. 
* To prevent Session Guard from instantly pausing again due to these stale responses, set the **Grace Period (requests)** to match your resource pool size (e.g., `10`). 
* Upon clicking Resume, the extension will ignore the next $N$ trigger responses.

### 4. Interactive Notifications & Audio Alerts
* **Popup Dialog**: Toggles an on-screen modal window to notify you immediately when a session expires, even if Burp is minimized.
* **Sound Alert**: Emits a system beep when a pause is triggered.
* **Burp Event Log**: Logs session pause and resume events to the Burp Suite system alert logs.

---

## Building

### Prerequisites
* Java 17 up to Java 25 (LTS)
* Gradle wrapper (included)

### Build the JAR
Run the shadow JAR build task to bundle dependencies:
```bash
# Windows
.\gradlew.bat shadowJar

# Linux/macOS
./gradlew shadowJar
```
The output JAR is compiled at: `build/libs/session-guard-1.0.0.jar`.

---

## Installation in Burp Suite

1. Open Burp Suite Professional.
2. Navigate to **Extensions** → **Installed** → **Add**.
3. Set Extension type to **Java**.
4. Choose the compiled JAR: `build/libs/session-guard-1.0.0.jar`.
5. Click **Next** to load the extension. You should see "Session Guard v1.0.0 loaded successfully".

---

## UI Guide & Configuration Options

| Control | Description | Default Value |
| :--- | :--- | :--- |
| **Status Indicator** | Displays `ACTIVE — Scanning normally` 🟢 or `PAUSED — Session Expired!` 🔴 | `ACTIVE` |
| **Requests Blocked / Grace** | Shows the count of blocked requests when paused, or remaining grace tokens | `0` |
| **Trigger Status Codes** | Input field for your target codes (e.g., `303, 401, 403`) | `303` |
| **Header Match Regex** | Optional regex pattern to match against response headers (e.g., `Location:.*login\.php`) | `(empty)` |
| **Body Match Regex** | Optional regex pattern to match against response body (e.g., `Your session has expired`) | `(empty)` |
| **Grace Period (requests)** | Number of trigger responses to ignore upon clicking Resume | `10` |
| **Tool Monitoring Checkboxes** | Select tools (Scanner, Extensions, Intruder, Repeater, Proxy) | `Scanner`, `Extensions` (ON) |
| **Show popup notification** | Enable modal popups on trigger | Checked |
| **Play sound alert** | Play an audible system beep on trigger | Checked |
| **Resume Scanning Button** | Resumes traffic, applying the configured Grace Period | Enabled when paused |
| **Pause Manually Button** | Manually pause scanning/traffic at any time | Enabled when active |
| **Clear Log** | Clears the detection log window | — |

---

## Architecture Overview

* **`SessionGuardExtension`**: The entry point implementing `BurpExtension` to register HTTP handlers and the UI tab.
* **`GateController`**: Thread-safe manager using a `CountDownLatch` state gate. Intercepted threads call `await()` to block without spinning the CPU, waking up synchronously upon `resume()`.
* **`SessionGuardHttpHandler`**: Implements Montoya's `HttpHandler`. It inspects responses for trigger codes on monitored tools to block requests on the gate when active.
* **`SessionGuardTab`**: A custom GUI panel built using Swing to provide live control and detection logs.


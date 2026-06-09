# Session Guard — Burp Suite Extension

A Burp Suite extension that **detects session/cookie expiry** during active scanning and **pauses all scanner traffic** until you update your credentials.

## The Problem

When cookies expire mid-scan, the target server returns HTTP redirects or error status codes (e.g., `303`, `401`, `403`). If you have a resource pool running concurrent requests (e.g., 10 concurrent requests), all in-flight requests will fail, and the scanner will continue queueing and firing hundreds of requests with stale tokens. This pollutes your scan logs and fails all test cases, forcing you to restart the entire scan from scratch.

## The Solution

Session Guard monitors HTTP traffic from your selected Burp Suite tools. When it detects any of your configured trigger status codes:

1. **Blocks Future Traffic Instantly**: Future requests are intercepted and held in a thread-safe gate (using `CountDownLatch` to sleep threads efficiently with zero CPU spin).
2. **Alerts You Immediately**: Triggers a popup alert dialog, plays an audible system beep, and writes a warning to the Burp Suite **Alerts** tab.
3. **Resumes Seamlessly**: Once you update your cookies/tokens in Burp's Cookie Jar or session headers, click **Resume Scanning** to release all queued requests.
4. **Project Persistence**: All your configured settings and detection logs are automatically saved and loaded directly from your Burp Suite project file.

---

## Operating Modes

| Feature | Mode 1: Plug-and-play (Default) | Mode 2: Strict Mode |
| :--- | :--- | :--- |
| **Setup Required** | None (Just install and scan) | Session Handling Rule in Burp |
| **Test Case Retention** | Loses a few in-flight test cases | **~100% test cases retained** |
| **Retry Logic** | Fails in-flight requests | Automatically re-issues held requests |
| **Grace Period** | ✅ Needed (drains stale pipeline) | ❌ Not needed (requests blocked before sending) |
| **Ideal For** | Quick scans, easy setup | Deep, comprehensive audits |

---

### Mode 1: Plug-and-play (Default)

**Setup:** None — just install the extension and scan.

**How it works:**

```
Scanner Request → goes to server → Response comes back
                                         ↓
                               ┌─ HTTP HANDLER ──────────────┐
                               │ Response matches trigger?    │
                               │   ↓ YES                      │
                               │ Validation probe (if set)    │
                               │   ↓ Confirmed expired        │
                               │ PAUSE gate + notify user     │
                               └──────────────────────────────┘
                                         ↓
                          All future requests BLOCKED
                          until user clicks ▶ Resume
```

**Steps:**
1. Configure your scan target and start an active scan.
2. Session Guard runs silently in the background.
3. **Cookie expires** → Extension triggers based on your configured status codes or regex patterns:
   - Scanner freezes (future requests held in queue).
   - Popup alert appears, system beep plays, and Burp Alerts tab shows critical notification.
4. **You** update cookies, tokens, and headers as needed.
5. Switch to the **Session Guard** tab and click **▶ Resume**.
6. All held requests resume with the updated credentials. *(Note: Requests that were already in-flight before the pause will return your configured trigger codes and be ignored via the Grace Period).*

---

### Mode 2: Strict Mode (~100% Test Case Retention)

Strict Mode uses Burp's native Session Handling Rules to block requests **before** they are sent. This means almost zero leaked requests with invalid cookies.

**How it works:**

```
Scanner Request arrives at Session Handling Rule
        ↓
   ┌─ SESSION GUARD ACTION (pre-request) ────────────┐
   │  • Gate already paused? → BLOCK immediately      │
   │  • Cooldown active? → pass through (0 overhead)  │
   │  • Cooldown expired? → probe validation URL      │
   │    • Session valid → reset cooldown, pass through │
   │    • Session expired → PAUSE gate, notify, BLOCK  │
   └──────────────────────────────────────────────────┘
        ↓ (request goes to server)
   Response comes back
        ↓
   ┌─ HTTP HANDLER (post-response, backup) ───────────┐
   │  • Response matches trigger (e.g. 303)?           │
   │    • Validation probe → false positive? → ignore  │
   │    • Real expiry → PAUSE gate immediately         │
   └──────────────────────────────────────────────────┘
        ↓
   All subsequent requests BLOCKED at the Action gate
   until user clicks ▶ Resume
```

Both the **Action** (pre-request check every ~30s) and the **HttpHandler** (post-response check) work together to catch session expiry as fast as possible.

---

#### Strict Mode Setup — Simple (Recommended)

Just one rule action. No macros needed.

**Step 1: Create Session Handling Rule**
1. Go to **Settings** → **Sessions** → **Session Handling Rules**.
2. Click **Add** to create a new rule.
3. Give it a description (e.g., `Session Guard`).

**Step 2: Add Rule Action**
1. Under **Rule Actions**, click **Add** → **Invoke a Burp extension**.
2. Select **Session Guard — Pause & Retry** from the dropdown.
3. Click **OK**.

**Step 3: Configure Scope**
1. Switch to the **Scope** tab at the top of the rule editor.
2. Under **Tools Scope**, select the tools you want to protect (e.g., **Scanner**, **Intruder**, **Repeater**).
3. Under **URL Scope**, select **Use suite scope** or define your target URLs explicitly.
4. Click **OK** to save.

**Step 4: Configure the Extension**
1. Go to the **Session Guard** tab in Burp.
2. Set **Trigger Status Codes** (e.g., `303, 401`).
3. Set **Validation URL** (e.g., `https://target.com/dashboard`).
4. Change **Operating Mode** to **Mode 2: Strict Mode**.

That's it! The extension will automatically probe the validation URL every ~30 seconds and pause instantly when the session expires.

---

#### Strict Mode Setup — Advanced (Zero Leaked Requests)

For **absolute zero leaked requests**, use Burp's "Check session is valid" macro approach. This adds one extra HTTP request before every scanner request but guarantees no request ever goes out with an expired cookie.

**Step 1: Record a Macro**
1. Go to **Settings** → **Sessions** → **Macros** section.
2. Click **Add**.
3. Burp will open a recorder. Navigate to your validation URL (e.g., `https://target.com/dashboard`) so it captures the request.
4. Select that single request and click **OK**.
5. Give it a name (e.g., `Session Guard Validation`) → **OK**.

**Step 2: Create Session Handling Rule**
1. In **Settings** → **Sessions** → **Session Handling Rules**, click **Add**.
2. Description: `Session Guard Strict Mode`.

**Step 3: Add "Check session is valid" Action**
1. Under **Rule Actions**, click **Add** → **Check session is valid**.
2. Configure it:

   - **Make request(s) to validate session:**
     - Select **Run macro** → choose the macro you recorded in Step 1.

   - **Inspect response to determine session validity:**
     - Under **HTTP headers**, check for your trigger (e.g., status code `303`, or a `Location:` header containing a login redirect).
     - Or under **Response body**, enter a regex that matches your login/error page.

   - **Define behavior dependent on session validity:**
     - Under **If session is invalid, perform the action below:**
     - Select **Invoke a Burp extension handler** → **Session Guard — Pause & Retry**.

3. Click **OK**.

**Step 4: Configure Scope**
1. Switch to the **Scope** tab.
2. **Tools**: Select Scanner, Intruder, Repeater (whichever you need).
3. **URL Scope**: Select **Use suite scope** or define explicitly.
4. Click **OK**.

**Step 5: Configure the Extension**
1. Go to the **Session Guard** tab.
2. Set **Trigger Status Codes** and **Validation URL**.
3. Change **Operating Mode** to **Mode 2: Strict Mode**.

With this setup, Burp checks the session BEFORE every request via the macro. If invalid, our extension is invoked, pauses the gate, and blocks all threads. **Zero requests leak through.**

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

### 3. Grace Period (Stale Pipeline Drain) — Mode 1 Only
> **Note**: Grace Period is only applicable in **Mode 1 (Plug-and-play)**. In Strict Mode (Mode 2), requests are blocked before they are sent, so there is no stale pipeline to drain.

If you have a resource pool of $N$ concurrent requests, $N-1$ requests might still be sent or in-flight immediately after the session expires. When you update the session cookie and resume scanning, those stale requests will eventually return the trigger status code. 
* To prevent Session Guard from instantly pausing again due to these stale responses, set the **Grace Period (requests)** to match your resource pool size (e.g., `10`). 
* Upon clicking Resume, the extension will ignore the next $N$ trigger responses.

### 4. Interactive Notifications & Audio Alerts
* **Popup Dialog**: Toggles an on-screen modal window to notify you immediately when a session expires, even if Burp is minimized.
* **Sound Alert**: Emits a system beep when a pause is triggered.
* **Burp Event Log**: Logs session pause and resume events to the Burp Suite system alert logs.

### 5. Validation Probe (False Positive Prevention)
Some Burp Scanner checks — notably **Web Cache Deception (WCD)** — intentionally strip the `Cookie` header from requests. The server responds with a redirect (e.g., `303`) because there is no session. Without protection, Session Guard would interpret this as a real session expiry and pause the scanner.

The **Validation Probe** prevents this by double-checking before pausing:

1. Set the **Validation URL** to any authenticated endpoint on your target (e.g., `https://target.com/dashboard`).
2. When a trigger response is detected, Session Guard sends a quick probe request to the Validation URL **with your real cookies from the Cookie Jar**.
3. If the probe returns a **normal (non-trigger) response** → the session is still alive → the original trigger was a **false positive** (e.g., WCD) → it is silently ignored and scanning continues.
4. If the probe **also triggers** (e.g., also returns `303`) → the session is truly expired → scanning is paused as usual.

> **Tip**: The Validation URL should be a lightweight, fast-loading authenticated page. Pick something that responds quickly.

This feature works in **both Mode 1 (Plug-and-play) and Mode 2 (Strict Mode)**.

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
| **Trigger Status Codes** ⚹ | Input field for your target codes (e.g., `303, 401, 403`) | `303` |
| **Header Match Regex** | Optional regex pattern to match against response headers (e.g., `Location:.*login\.php`) | `(empty)` |
| **Body Match Regex** | Optional regex pattern to match against response body (e.g., `Your session has expired`) | `(empty)` |
| **Validation URL** ⚹ | URL to probe before pausing. Prevents false positives from WCD and similar scanner checks. | `(empty)` |
| **Grace Period (requests)** | Number of trigger responses to ignore upon clicking Resume (**Mode 1 only**) | `10` |
| **Show popup notification** | Enable modal popups on trigger | Checked |
| **Play sound alert** | Play an audible system beep on trigger | Checked |
| **Operating Mode** | Mode 1 (Plug-and-play) or Mode 2 (Strict Mode) | Mode 1 |
| **Resume Scanning Button** | Resumes traffic, applying the configured Grace Period | Enabled when paused |
| **Pause Manually Button** | Manually pause scanning/traffic at any time | Enabled when active |
| **Clear Log** | Clears the detection log window | — |

> ⚹ = Required fields for proper extension operation

---

## Architecture Overview

* **`SessionGuardExtension`**: The entry point implementing `BurpExtension` to register HTTP handlers, session handling action, and the UI tab.
* **`GateController`**: Thread-safe manager using a `CountDownLatch` state gate. Intercepted threads call `await()` to block without spinning the CPU, waking up synchronously upon `resume()`. Also holds a shared `isProbing` flag (with CAS-based `startProbing()`) used by the Validation Probe feature to prevent recursive trigger detection and ensure only one thread probes at a time.
* **`SessionGuardHttpHandler`**: Implements Montoya's `HttpHandler`. It inspects responses for trigger codes, runs a validation probe when configured, and blocks requests on the gate when active. Works in both modes as a response-based detection layer.
* **`SessionGuardAction`**: Implements Montoya's `SessionHandlingAction` for Strict Mode. Invoked by Burp's Session Handling Rules, it uses a smart cooldown-based validation probe (~1 probe every 30 seconds) and blocks threads until resume. Provides the pre-request blocking layer for Mode 2.
* **`SessionGuardTab`**: A custom GUI panel built using Swing to provide live control, configuration, and detection logs. All settings are persisted to the Burp project file.

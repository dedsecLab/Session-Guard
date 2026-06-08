package sessionguard;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import burp.api.montoya.persistence.PersistedObject;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Custom Burp Suite tab — "Session Guard"
 *
 * Displays:
 *   - Live status indicator (ACTIVE / PAUSED)
 *   - Blocked request counter + grace counter
 *   - Configurable trigger status codes
 *   - Tool monitoring checkboxes (Scanner, Extensions, Repeater, Intruder, Proxy)
 *   - Grace period field (to drain stale pipeline after resume)
 *   - Popup and sound toggle checkboxes
 *   - Detection log with timestamps and URLs
 *   - Resume / Pause / Clear Log buttons
 */
public class SessionGuardTab {

    private final MontoyaApi api;
    private final GateController gate;

    // UI components
    private final JPanel mainPanel;
    private final JLabel statusLabel;
    private final JLabel statusIcon;
    private final JLabel blockedCountLabel;
    private final JTextArea logArea;
    private final JTextField statusCodesField;
    private final JTextField headerRegexField;
    private final JTextField bodyRegexField;
    private final JTextField validationUrlField;
    private final JTextField graceCountField;
    private final JCheckBox popupCheckbox;
    private final JCheckBox soundCheckbox;
    private final JComboBox<String> modeSelector;
    private final JButton resumeButton;
    private final JButton pauseButton;

    // Tool monitoring checkboxes
    private final Map<ToolType, JCheckBox> toolCheckboxes = new EnumMap<>(ToolType.class);

    // Refresh timer for blocked count display
    private final Timer refreshTimer;

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public SessionGuardTab(MontoyaApi api, GateController gate) {
        this.api = api;
        this.gate = gate;

        // Initialize UI components
        this.statusLabel = new JLabel("ACTIVE — Scanning normally");
        this.statusIcon = new JLabel("●");
        this.blockedCountLabel = new JLabel("Requests blocked: 0");
        this.logArea = new JTextArea();
        this.statusCodesField = new JTextField("303", 20);
        this.headerRegexField = new JTextField("", 20);
        this.bodyRegexField = new JTextField("", 20);
        this.validationUrlField = new JTextField("", 20);
        this.graceCountField = new JTextField("10", 5);
        this.popupCheckbox = new JCheckBox("Show popup notification", true);
        this.soundCheckbox = new JCheckBox("Play sound alert", true);
        this.modeSelector = new JComboBox<>(new String[]{
            "Mode 1: Plug-and-play (Extension handles detection)",
            "Mode 2: Strict Mode (Burp Session Rules handle detection)"
        });
        this.resumeButton = new JButton("  ▶  Resume Scanning  ");
        this.pauseButton = new JButton("  ⏸  Pause Manually  ");

        // Build the panel
        this.mainPanel = buildUI();

        // Timer to refresh blocked count every second (only when paused)
        this.refreshTimer = new Timer(1000, e -> refreshBlockedCount());
        this.refreshTimer.start();
        
        // Load persisted settings from project
        loadSettings();
    }

    /**
     * Construct the complete Swing UI for the Session Guard tab.
     */
    private JPanel buildUI() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // ═══════════════════════════════════════
        // HEADER — Title + Status
        // ═══════════════════════════════════════
        JPanel headerPanel = new JPanel(new BorderLayout(10, 5));
        headerPanel.setBorder(new EmptyBorder(0, 0, 10, 0));

        JLabel titleLabel = new JLabel("SESSION GUARD");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));
        headerPanel.add(titleLabel, BorderLayout.NORTH);

        // Status row
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        statusIcon.setFont(statusIcon.getFont().deriveFont(22f));
        statusIcon.setForeground(new Color(0, 180, 0));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 14f));
        statusLabel.setForeground(new Color(0, 180, 0));
        statusPanel.add(statusIcon);
        statusPanel.add(statusLabel);
        statusPanel.add(Box.createHorizontalStrut(30));
        blockedCountLabel.setFont(blockedCountLabel.getFont().deriveFont(Font.PLAIN, 13f));
        statusPanel.add(blockedCountLabel);
        headerPanel.add(statusPanel, BorderLayout.SOUTH);

        panel.add(headerPanel, BorderLayout.NORTH);

        // ═══════════════════════════════════════
        // CENTER — Config + Log
        // ═══════════════════════════════════════
        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));

        // — Configuration Section (top half) —
        JPanel configWrapper = new JPanel();
        configWrapper.setLayout(new BoxLayout(configWrapper, BoxLayout.Y_AXIS));

        // --- Trigger & Alert Config ---
        JPanel triggerPanel = new JPanel(new GridBagLayout());
        triggerPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor"), 1),
                " Trigger & Alerts ",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 8, 5, 8);
        gbc.anchor = GridBagConstraints.WEST;

        // Row 0: Status codes
        gbc.gridx = 0; gbc.gridy = 0;
        triggerPanel.add(new JLabel("Trigger Status Codes:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        statusCodesField.setToolTipText("Comma-separated status codes (e.g., 303, 401, 403)");
        triggerPanel.add(statusCodesField, gbc);

        // Row 1: Header regex
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        triggerPanel.add(new JLabel("Header Match Regex:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        headerRegexField.setToolTipText("Regex to match within response headers (leave empty to ignore)");
        triggerPanel.add(headerRegexField, gbc);

        // Row 2: Body regex
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        triggerPanel.add(new JLabel("Body Match Regex:"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        bodyRegexField.setToolTipText("Regex to match within response body (leave empty to ignore)");
        triggerPanel.add(bodyRegexField, gbc);

        // Row 3: Validation URL
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        triggerPanel.add(new JLabel("Validation URL:"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        validationUrlField.setToolTipText(
                "URL to probe before pausing (e.g., https://target.com/dashboard). " +
                "If this URL returns a normal (non-trigger) response, the trigger is ignored as a false positive. " +
                "Prevents WCD and similar scanner checks from stopping the scan. Leave empty to disable."
        );
        triggerPanel.add(validationUrlField, gbc);

        // Row 4: Grace period
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        triggerPanel.add(new JLabel("Grace Period (requests):"), gbc);
        gbc.gridx = 1; gbc.gridy = 4;
        graceCountField.setToolTipText(
                "After Resume, ignore this many trigger responses to drain the stale pipeline. " +
                "Set this to your resource pool's concurrent request count (e.g., 10)."
        );
        triggerPanel.add(graceCountField, gbc);
        gbc.gridx = 2; gbc.gridy = 4; gbc.gridwidth = 2;
        JLabel graceHint = new JLabel("(match your resource pool size — prevents false re-triggers)");
        graceHint.setFont(graceHint.getFont().deriveFont(Font.ITALIC, 11f));
        triggerPanel.add(graceHint, gbc);

        // Row 5: Checkboxes
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1;
        triggerPanel.add(popupCheckbox, gbc);
        gbc.gridx = 1; gbc.gridy = 5;
        triggerPanel.add(soundCheckbox, gbc);

        // Row 6: Operating Mode
        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        triggerPanel.add(new JLabel("Operating Mode:"), gbc);
        gbc.gridx = 1; gbc.gridy = 6; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        modeSelector.setToolTipText("Select Mode 2 if you configured Burp Session Handling Rules for 100% test case retention.");
        triggerPanel.add(modeSelector, gbc);

        configWrapper.add(triggerPanel);
        configWrapper.add(Box.createVerticalStrut(6));

        // --- Tool Monitoring Section ---
        JPanel toolPanel = new JPanel(new GridBagLayout());
        toolPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor"), 1),
                " Tool Monitoring ",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        GridBagConstraints tgbc = new GridBagConstraints();
        tgbc.insets = new Insets(4, 8, 4, 12);
        tgbc.anchor = GridBagConstraints.WEST;

        // Row 0: Info label
        tgbc.gridx = 0; tgbc.gridy = 0; tgbc.gridwidth = 5;
        JLabel toolInfoLabel = new JLabel("Select which Burp tools should be monitored and paused:");
        toolInfoLabel.setFont(toolInfoLabel.getFont().deriveFont(Font.ITALIC, 11f));
        toolPanel.add(toolInfoLabel, tgbc);

        // Row 1: Tool checkboxes
        tgbc.gridy = 1; tgbc.gridwidth = 1;

        // Scanner — default ON
        tgbc.gridx = 0;
        JCheckBox scannerCb = new JCheckBox("Scanner", true);
        scannerCb.setToolTipText("Monitor Burp's built-in active/passive scanner");
        toolCheckboxes.put(ToolType.SCANNER, scannerCb);
        toolPanel.add(scannerCb, tgbc);

        // Extensions — default ON
        tgbc.gridx = 1;
        JCheckBox extensionsCb = new JCheckBox("Extensions", true);
        extensionsCb.setToolTipText("Monitor extension traffic (Active Scan++, custom extensions, etc.)");
        toolCheckboxes.put(ToolType.EXTENSIONS, extensionsCb);
        toolPanel.add(extensionsCb, tgbc);

        // Intruder — default OFF
        tgbc.gridx = 2;
        JCheckBox intruderCb = new JCheckBox("Intruder", false);
        intruderCb.setToolTipText("Monitor Intruder attack traffic");
        toolCheckboxes.put(ToolType.INTRUDER, intruderCb);
        toolPanel.add(intruderCb, tgbc);

        // Repeater — default OFF
        tgbc.gridx = 3;
        JCheckBox repeaterCb = new JCheckBox("Repeater", false);
        repeaterCb.setToolTipText("Monitor Repeater requests");
        toolCheckboxes.put(ToolType.REPEATER, repeaterCb);
        toolPanel.add(repeaterCb, tgbc);

        // Proxy — default OFF
        tgbc.gridx = 4;
        JCheckBox proxyCb = new JCheckBox("Proxy", false);
        proxyCb.setToolTipText("Monitor Proxy traffic (may cause browser hangs if paused!)");
        toolCheckboxes.put(ToolType.PROXY, proxyCb);
        toolPanel.add(proxyCb, tgbc);

        configWrapper.add(toolPanel);

        centerPanel.add(configWrapper, BorderLayout.NORTH);

        // — Detection Log —
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Component.borderColor"), 1),
                " Detection Log ",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setLineWrap(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(600, 250));
        logPanel.add(scrollPane, BorderLayout.CENTER);

        centerPanel.add(logPanel, BorderLayout.CENTER);

        panel.add(centerPanel, BorderLayout.CENTER);

        // ═══════════════════════════════════════
        // FOOTER — Action Buttons
        // ═══════════════════════════════════════
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        buttonPanel.setBorder(new EmptyBorder(5, 0, 0, 0));

        // Resume button styling
        resumeButton.setFont(resumeButton.getFont().deriveFont(Font.BOLD, 13f));
        resumeButton.setEnabled(false);
        resumeButton.addActionListener(e -> onResume());

        // Pause button
        pauseButton.setFont(pauseButton.getFont().deriveFont(Font.PLAIN, 13f));
        pauseButton.addActionListener(e -> onPauseManually());

        // Clear log button
        JButton clearButton = new JButton("  🗑  Clear Log  ");
        clearButton.setFont(clearButton.getFont().deriveFont(Font.PLAIN, 13f));
        clearButton.addActionListener(e -> onClearLog());

        buttonPanel.add(resumeButton);
        buttonPanel.add(pauseButton);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(clearButton);

        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Auto-save listeners for configuration changes
        java.awt.event.ActionListener saveAction = e -> saveSettings();
        java.awt.event.FocusAdapter saveFocus = new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent e) { saveSettings(); }
        };
        
        popupCheckbox.addActionListener(saveAction);
        soundCheckbox.addActionListener(saveAction);
        modeSelector.addActionListener(saveAction);
        statusCodesField.addFocusListener(saveFocus);
        headerRegexField.addFocusListener(saveFocus);
        bodyRegexField.addFocusListener(saveFocus);
        validationUrlField.addFocusListener(saveFocus);
        graceCountField.addFocusListener(saveFocus);
        for (JCheckBox cb : toolCheckboxes.values()) {
            cb.addActionListener(saveAction);
        }

        return panel;
    }

    // ═══════════════════════════════════════════
    // PUBLIC API — called by SessionGuardHttpHandler
    // ═══════════════════════════════════════════

    /**
     * @return the main panel to register with Burp's tab system
     */
    public JPanel getPanel() {
        return mainPanel;
    }

    /**
     * Check if the given tool type is currently enabled for monitoring.
     *
     * @param toolType the Burp tool type to check
     * @return true if the user has checked the corresponding checkbox
     */
    public boolean isToolMonitored(ToolType toolType) {
        JCheckBox cb = toolCheckboxes.get(toolType);
        return cb != null && cb.isSelected();
    }

    /**
     * Add a log entry to the detection log area (thread-safe).
     */
    public void addLogEntry(String entry) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(entry + "\n");
            // Auto-scroll to bottom
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    /**
     * Update the visual status indicator (thread-safe).
     */
    public void updateStatus(boolean paused) {
        SwingUtilities.invokeLater(() -> {
            if (paused) {
                statusIcon.setForeground(new Color(220, 40, 40));
                statusLabel.setText("PAUSED — Session Expired! Update cookies and click Resume.");
                statusLabel.setForeground(new Color(220, 40, 40));
                resumeButton.setEnabled(true);
                pauseButton.setEnabled(false);
            } else {
                statusIcon.setForeground(new Color(0, 180, 0));
                statusLabel.setText("ACTIVE — Scanning normally");
                statusLabel.setForeground(new Color(0, 180, 0));
                resumeButton.setEnabled(false);
                pauseButton.setEnabled(true);
            }
        });
    }

    /**
     * Parse the trigger status codes from the configuration text field.
     * Returns a set of integers. Defaults to {303} if parsing fails.
     */
    public Set<Integer> getTriggerStatusCodes() {
        try {
            String text = statusCodesField.getText().trim();
            if (text.isEmpty()) {
                return Collections.singleton(303);
            }
            return Arrays.stream(text.split("[,;\\s]+"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(Integer::parseInt)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        } catch (NumberFormatException e) {
            api.logging().logToError("Session Guard: invalid status codes in config, defaulting to 303");
            return Collections.singleton(303);
        }
    }

    /**
     * Parse the grace count from the configuration text field.
     * Defaults to 10 if parsing fails.
     */
    public int getGraceCount() {
        try {
            return Math.max(0, Integer.parseInt(graceCountField.getText().trim()));
        } catch (NumberFormatException e) {
            return 10;
        }
    }

    public String getHeaderRegex() {
        return headerRegexField.getText().trim();
    }

    public String getBodyRegex() {
        return bodyRegexField.getText().trim();
    }

    /**
     * @return the validation URL text, empty string if not configured
     */
    public String getValidationUrl() {
        return validationUrlField.getText().trim();
    }

    /**
     * @return true if the popup notification checkbox is checked
     */
    public boolean isPopupEnabled() {
        return popupCheckbox.isSelected();
    }

    /**
     * @return true if the sound alert checkbox is checked
     */
    public boolean isSoundEnabled() {
        return soundCheckbox.isSelected();
    }
    
    /**
     * @return true if the plug-and-play detection is enabled
     */
    public boolean isPluginDetectionEnabled() {
        return modeSelector.getSelectedIndex() == 0;
    }
    
    /**
     * Save settings to Burp's project persistence
     */
    public void saveSettings() {
        PersistedObject data = api.persistence().extensionData();
        data.setString("SG_StatusCodes", statusCodesField.getText());
        data.setString("SG_HeaderRegex", headerRegexField.getText());
        data.setString("SG_BodyRegex", bodyRegexField.getText());
        data.setString("SG_ValidationUrl", validationUrlField.getText());
        data.setString("SG_GraceCount", graceCountField.getText());
        data.setBoolean("SG_Popup", popupCheckbox.isSelected());
        data.setBoolean("SG_Sound", soundCheckbox.isSelected());
        data.setInteger("SG_OperatingMode", modeSelector.getSelectedIndex());
        
        for (Map.Entry<ToolType, JCheckBox> entry : toolCheckboxes.entrySet()) {
            data.setBoolean("SG_Tool_" + entry.getKey().name(), entry.getValue().isSelected());
        }
        
        data.setString("SG_Log", logArea.getText());
    }

    /**
     * Load settings from Burp's project persistence
     */
    public void loadSettings() {
        PersistedObject data = api.persistence().extensionData();
        
        String statusCodes = data.getString("SG_StatusCodes");
        if (statusCodes != null) statusCodesField.setText(statusCodes);
        
        String headerRegex = data.getString("SG_HeaderRegex");
        if (headerRegex != null) headerRegexField.setText(headerRegex);

        String bodyRegex = data.getString("SG_BodyRegex");
        if (bodyRegex != null) bodyRegexField.setText(bodyRegex);

        String validationUrl = data.getString("SG_ValidationUrl");
        if (validationUrl != null) validationUrlField.setText(validationUrl);

        String graceCount = data.getString("SG_GraceCount");
        if (graceCount != null) graceCountField.setText(graceCount);
        
        Boolean popup = data.getBoolean("SG_Popup");
        if (popup != null) popupCheckbox.setSelected(popup);
        
        Boolean sound = data.getBoolean("SG_Sound");
        if (sound != null) soundCheckbox.setSelected(sound);

        Integer operatingMode = data.getInteger("SG_OperatingMode");
        if (operatingMode != null && operatingMode >= 0 && operatingMode < modeSelector.getItemCount()) {
            modeSelector.setSelectedIndex(operatingMode);
        }
        
        for (Map.Entry<ToolType, JCheckBox> entry : toolCheckboxes.entrySet()) {
            Boolean toolEnabled = data.getBoolean("SG_Tool_" + entry.getKey().name());
            if (toolEnabled != null) {
                entry.getValue().setSelected(toolEnabled);
            }
        }
        
        String log = data.getString("SG_Log");
        if (log != null) logArea.setText(log);
    }

    // ═══════════════════════════════════════════
    // BUTTON HANDLERS
    // ═══════════════════════════════════════════

    private void onResume() {
        int graceCount = getGraceCount();
        gate.resume(graceCount);
        updateStatus(false);

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);
        int blocked = gate.getBlockedCount();
        String msg = String.format(
                "[%s]  ▶ RESUMED — %d requests were held back, grace period: %d responses",
                timestamp, blocked, graceCount
        );
        addLogEntry(msg);

        api.logging().raiseInfoEvent(
                "Session Guard: scanning RESUMED. " + blocked + " requests held back. " +
                "Grace period: next " + graceCount + " trigger responses will be ignored."
        );
        api.logging().logToOutput("Session Guard: " + msg);
    }

    private void onPauseManually() {
        if (!gate.isPaused()) {
            gate.pause();
            updateStatus(true);

            String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);
            String msg = String.format("[%s]  ⏸ MANUALLY PAUSED by user", timestamp);
            addLogEntry(msg);

            api.logging().raiseInfoEvent("Session Guard: scanner MANUALLY PAUSED by user.");
            api.logging().logToOutput("Session Guard: " + msg);
        }
    }

    private void onClearLog() {
        logArea.setText("");
        saveSettings();
    }

    /**
     * Periodic refresh of the blocked request counter (called by Swing timer).
     */
    private void refreshBlockedCount() {
        if (gate.isPaused()) {
            blockedCountLabel.setText("Requests blocked: " + gate.getBlockedCount());
        } else {
            int grace = gate.getGraceRemaining();
            if (grace > 0) {
                blockedCountLabel.setText("Grace remaining: " + grace + " responses");
            } else {
                blockedCountLabel.setText("Requests blocked: 0");
            }
        }
    }
}

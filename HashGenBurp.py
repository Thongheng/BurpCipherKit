# -*- coding: utf-8 -*-
# CipherKit - Burp Suite Extension entry point.
# Loaded directly by Burp Suite (Jython). All logic lives in core/ and ui/.

from __future__ import print_function
import os, sys, json, traceback, itertools

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation,
    IMessageEditorTab, IMessageEditorTabFactory, ISessionHandlingAction
)

from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JButton, JComboBox, JCheckBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, SwingUtilities,
    BoxLayout, Box
)
from javax.swing.border import EmptyBorder, AbstractBorder
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout, Component
)
from java.awt.event import FocusAdapter

# Make sure Burp can find our packages — use callbacks.getExtensionFilename()
# at runtime instead of __file__ (not available in Jython/Burp context)
import inspect as _inspect
_here = os.path.dirname(os.path.abspath(_inspect.getfile(_inspect.currentframe())))
if _here not in sys.path:
    sys.path.insert(0, _here)

from core.snippet_manager import SnippetManager
from core.crypto_snippet_manager import CryptoSnippetManager
from core.app_setting_manager import AppSettingManager
from core.body_parser import parse_body, serialize_body
from core.crypto_engine import CryptoEngine
from core.crypto_snippet_engine import CryptoSnippetEngine
from core.utils import _MAX_KF_FIELDS, _extract_request_path
from ui.editor_tab import HashGenEditorTab
from ui.components.rounded_border import RoundedBorder, _roundedCompound
from ui.components.custom_data_panel import CustomDataPanel, CompactCustomDataPanel
from ui.components.listeners import PayloadDocumentListener, PayloadFocusListener


class _DisabledEditorTab(IMessageEditorTab):
    """Fail-closed IMessageEditorTab placeholder so Burp never receives None."""

    def __init__(self, caption="CipherKit"):
        self._caption = caption
        self._panel = JPanel(BorderLayout())
        self._current_message = None

    def getTabCaption(self):
        return self._caption

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        return False

    def setMessage(self, content, isRequest):
        self._current_message = content

    def getMessage(self):
        return self._current_message

    def isModified(self):
        return False

    def getSelectedData(self):
        return None

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory, ISessionHandlingAction):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CipherKit")

        # Redirect stdout/stderr to Burp's output
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Snippet managers
        ext_file   = callbacks.getExtensionFilename()
        script_dir = os.path.dirname(os.path.abspath(ext_file))
        snippets_path        = os.path.join(script_dir, "snippets.json")
        crypto_snippets_path = os.path.join(script_dir, "crypto_snippets.json")
        app_settings_path = os.path.join(script_dir, "app_settings.json")
        self.snippet_manager        = SnippetManager(snippets_path)
        self.crypto_snippet_manager = CryptoSnippetManager(crypto_snippets_path)
        self.app_setting_manager    = AppSettingManager(app_settings_path)

        # Build main tab UI synchronously
        SwingUtilities.invokeAndWait(self._buildUI)

        # Register all factories
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerSessionHandlingAction(self)  # Intruder Auto-Rehash

        # Register the main HashGen tab
        callbacks.addSuiteTab(self)

        print("[+] CipherKit extension loaded successfully")
        print("[*] Snippets file:       %s" % snippets_path)
        print("[*] Crypto snippets:     %s" % crypto_snippets_path)
        print("[*] App settings file:   %s" % app_settings_path)
        print("[*] CipherKit tab added to request editor views")


    # -------------------------------------------------------------------------
    # ISessionHandlingAction implementation — Intruder Auto-Rehash
    # -------------------------------------------------------------------------
    def getActionName(self):
        """Name shown in Burp Session Handling Rules action picker."""
        return "CipherKit - Auto-Rehash"

    def performAction(self, currentRequest, macroItems):
        """
        Called by Burp Session Handling Rules for every Intruder/Repeater request.
        Finds a matching app setting for the request URL, re-computes the hash field,
        and injects the new value back into the request body.
        """
        try:
            req_info = self._helpers.analyzeRequest(currentRequest.getRequest())
            headers  = req_info.getHeaders()
            body_offset = req_info.getBodyOffset()
            body_bytes  = currentRequest.getRequest()[body_offset:]
            body_str    = self._helpers.bytesToString(body_bytes)

            if not body_str or not body_str.strip():
                return  # nothing to sign

            # Extract URL path for app setting lookup
            url_path = _extract_request_path(req_info)

            # Find a matching app setting
            app_name, app, pattern, ep = self.app_setting_manager.find_by_url(url_path)
            if not app:
                return  # no app setting matched — leave request unchanged

            # Extract content-type
            content_type = ""
            for h in headers:
                if h.lower().startswith("content-type:"):
                    content_type = h[len("content-type:"):].strip()
                    break

            # Parse body
            payload = parse_body(body_str, content_type)
            if not payload:
                return

            # Build params from app setting
            algo_name   = app.get("algorithm", "")
            secret      = app.get("secret", "")
            custom_data = app.get("custom_data", {})
            if ep and "custom_data" in ep:
                custom_data = ep["custom_data"]
            hash_field  = app.get("hash_field", "hash")
            keys_order  = None
            if ep and ep.get("keys_order"):
                keys_order = [k.strip() for k in ep["keys_order"].split(",") if k.strip()]

            snippet = self.snippet_manager.get_snippet(algo_name)
            if not snippet:
                print("[CipherKit] Auto-Rehash: snippet '%s' not found for app setting '%s'" % (algo_name, app_name))
                return

            result, _ = CryptoEngine.execute_snippet(
                snippet["code"], payload, secret, custom_data, keys_order
            )

            if not result or str(result).startswith("Error"):
                print("[CipherKit] Auto-Rehash error: %s" % result)
                return

            result_str = str(result)
            if self._globalUppercaseHashChk.isSelected():
                result_str = result_str.upper()

            # Inject the new hash back into the body
            payload[hash_field] = result_str
            new_body = serialize_body(payload, body_str, content_type)
            new_body_bytes = self._helpers.stringToBytes(new_body)
            new_request = self._helpers.buildHttpMessage(headers, new_body_bytes)
            currentRequest.setRequest(new_request)

            print("[CipherKit] Auto-Rehash: app_setting='%s' pattern='%s' hash_field='%s' value='%s'" % (
                app_name, pattern, hash_field, result_str[:40]
            ))

        except Exception as e:
            print("[CipherKit] Auto-Rehash exception: %s" % str(e))
            import traceback as _tb
            print(_tb.format_exc())

    # -------------------------------------------------------------------------
    # ITab implementation
    # -------------------------------------------------------------------------
    def getTabCaption(self):
        return "CipherKit"

    def getUiComponent(self):
        return self._mainPanel

    # -------------------------------------------------------------------------
    # IMessageEditorTabFactory implementation
    # -------------------------------------------------------------------------
    def createNewInstance(self, controller, editable):
        try:
            return HashGenEditorTab(self, controller, editable)
        except Exception as e:
            print("[CipherKit] ERROR creating inline tab: %s" % e)
            print(traceback.format_exc())
            return _DisabledEditorTab()

    # -------------------------------------------------------------------------
    # IContextMenuFactory implementation
    # -------------------------------------------------------------------------
    def createMenuItems(self, invocation):
        from javax.swing import JMenuItem
        menu_items = []

        ctx = invocation.getInvocationContext()
        valid_contexts = [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]

        if ctx in valid_contexts:
            item = JMenuItem("Send to CipherKit")
            item.addActionListener(lambda event: self._onContextMenuSend(invocation))
            menu_items.append(item)

        return menu_items if menu_items else None

    def _onContextMenuSend(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            request = messages[0].getRequest()
            if request:
                analyzed = self._helpers.analyzeRequest(request)
                body_offset = analyzed.getBodyOffset()
                body_bytes = request[body_offset:]
                body_str = self._helpers.bytesToString(body_bytes)

                if body_str and body_str.strip():
                    try:
                        parsed = json.loads(body_str)
                        body_str = json.dumps(parsed, indent=2)
                    except:
                        pass

                    self._payloadArea.setText(body_str)
                    self._tryExtractKeys()

                    parent = self._mainPanel.getParent()
                    if parent:
                        idx = parent.indexOfComponent(self._mainPanel)
                        if idx >= 0:
                            parent.setSelectedIndex(idx)

                    self._tabbedPane.setSelectedIndex(0)
                    print("[*] Request body sent to CipherKit Hash tab")

    # -------------------------------------------------------------------------
    # Build the Main Tab UI
    # -------------------------------------------------------------------------
    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))


        # Tabbed pane for Generator / Crypto / Editor
        self._tabbedPane = JTabbedPane()
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)

        generatorPanel = self._buildGeneratorTab()
        cryptoPanel        = self._buildCryptoTab()
        editorPanel        = self._buildEditorTab()
        cryptoEditorPanel  = self._buildCryptoEditorTab()
        keyFinderPanel     = self._buildKeyFinderTab()

        settingPanel = self._buildSettingTab()
        timestampPanel = self._buildTimestampTab()

        self._tabbedPane.addTab("Hash", generatorPanel)
        self._tabbedPane.addTab("Crypto", cryptoPanel)
        self._tabbedPane.addTab("Key Finder", keyFinderPanel)
        self._tabbedPane.addTab("Hash Editor", editorPanel)
        self._tabbedPane.addTab("Crypto Editor", cryptoEditorPanel)
        self._tabbedPane.addTab("AppSetting", settingPanel)
        self._tabbedPane.addTab("Timestamp", timestampPanel)

        # Global session-level settings bar (persists until Burp is restarted)
        globalBar = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 2))
        # Active output mode: controls what the Hash tab's output shows
        globalBar.add(JLabel("Hash tab output:"))
        self._activeOutputCombo = JComboBox(["Hash", "Crypto"])
        self._activeOutputCombo.setToolTipText(
            "Hash: output shows the generated hash value\n"
            "Crypto: output shows decrypted field value (editable, auto-encrypts on change)"
        )
        globalBar.add(self._activeOutputCombo)
        # Global auto-encrypt toggle
        self._globalAutoEncryptChk = JCheckBox("Auto-encrypt on edit", True)
        self._globalAutoEncryptChk.setToolTipText(
            "Session-wide toggle: uncheck to disable auto-encrypt in all CipherKit request tabs"
        )
        globalBar.add(self._globalAutoEncryptChk)
        # Global uppercase hash toggle
        self._globalUppercaseHashChk = JCheckBox("Uppercase hash", True)
        self._globalUppercaseHashChk.setToolTipText(
            "Session-wide toggle: check to force all generated hashes to uppercase"
        )
        globalBar.add(self._globalUppercaseHashChk)
        self._mainPanel.add(globalBar, BorderLayout.SOUTH)

    # -------------------------------------------------------------------------
    # Generator Tab
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # AppSetting Tab (main CipherKit)
    # -------------------------------------------------------------------------
    def _buildSettingTab(self):
        mainPanel = JPanel(BorderLayout(0, 8))
        mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Top: App selector row
        topRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        topRow.add(JLabel("App Setting:"))
        
        # Build combo box with current app names
        names = ["(none)"] + self.app_setting_manager.get_all_names()
        self._settingCombo = JComboBox(names)
        self._settingCombo.setPreferredSize(Dimension(200, 26))
        self._settingCombo.setToolTipText("Select an existing app setting to view or load")
        self._settingCombo.addActionListener(lambda e: self._onSettingComboChange())
        topRow.add(self._settingCombo)

        _loadBtn = JButton("Load Config", actionPerformed=self._onSettingSelected)
        _loadBtn.setToolTipText("Load the selected app setting into the Hash and Crypto tabs")
        topRow.add(_loadBtn)
        
        mainPanel.add(topRow, BorderLayout.NORTH)

        # Center: formatted summary area
        self._settingSummaryArea = JTextArea()
        self._settingSummaryArea.setEditable(False)
        self._settingSummaryArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._settingSummaryArea.setBorder(EmptyBorder(5, 5, 5, 5))
        
        mainPanel.add(JScrollPane(self._settingSummaryArea), BorderLayout.CENTER)
        
        # Bottom: actions panel
        actRow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        self._saveNewSettingBtn = JButton("Save New", actionPerformed=self._onSaveNewSetting)
        self._updateSettingBtn  = JButton("Update Existing", actionPerformed=self._onUpdateSetting)
        self._deleteSettingBtn  = JButton("Delete", actionPerformed=self._onDeleteSetting)
        
        self._saveNewSettingBtn.setToolTipText("Save current UI config as a new app setting")
        self._updateSettingBtn.setToolTipText("Overwrite the selected app setting with current UI config")
        
        actRow.add(self._saveNewSettingBtn)
        actRow.add(self._updateSettingBtn)
        actRow.add(self._deleteSettingBtn)
        
        mainPanel.add(actRow, BorderLayout.SOUTH)
        
        return mainPanel

    def _buildTimestampTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # ---- Left: Config panel (styled just like other tabs' left side) ----
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        lgbc = GridBagConstraints()
        lgbc.insets  = Insets(3, 4, 3, 4)
        lgbc.anchor  = GridBagConstraints.NORTHWEST
        lgbc.gridx   = 0
        lgbc.weightx = 1.0
        lgbc.fill    = GridBagConstraints.HORIZONTAL

        # Section Label
        lgbc.gridy = 0
        lbl = JLabel("Timestamp Options:")
        leftPanel.add(lbl, lgbc)

        # Checkbox: Auto-copy
        lgbc.gridy = 1
        lgbc.insets = Insets(10, 4, 3, 4)
        self._tsAutoCopyChk = JCheckBox("Auto-copy to clipboard", True)
        leftPanel.add(self._tsAutoCopyChk, lgbc)

        # Button: Get Timestamp
        lgbc.gridy = 2
        lgbc.insets = Insets(20, 4, 4, 4)
        tsBtn = JButton("Get Timestamp")
        leftPanel.add(tsBtn, lgbc)

        # Button: Copy to Clipboard
        lgbc.gridy = 3
        lgbc.insets = Insets(10, 4, 4, 4)
        copyBtn = JButton("Copy to Clipboard")
        leftPanel.add(copyBtn, lgbc)

        # Spacer to push items to the top
        lgbc.gridy = 4
        lgbc.weighty = 1.0
        lgbc.insets = Insets(0, 0, 0, 0)
        leftPanel.add(JPanel(), lgbc)

        # ---- Right: Text areas with label (matching Hash/Crypto tabs' right side) ----
        rightPanel = JPanel(GridBagLayout())
        rgbc = GridBagConstraints()
        rgbc.gridx   = 0
        rgbc.weightx = 1.0
        rgbc.fill    = GridBagConstraints.HORIZONTAL
        rgbc.insets  = Insets(0, 0, 2, 0)

        # Output label
        rgbc.gridy  = 0; rgbc.weighty = 0
        rightPanel.add(JLabel("Timestamp Output:"), rgbc)

        # Output scroll pane
        rgbc.gridy  = 1; rgbc.weighty = 1.0; rgbc.fill = GridBagConstraints.BOTH
        tsOutputArea = JTextArea(3, 40)
        tsOutputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        tsOutputArea.setLineWrap(True)
        tsOutputArea.setWrapStyleWord(True)
        tsOutputArea.setEditable(False)
        outputScroll = JScrollPane(tsOutputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(outputScroll, rgbc)

        # Combine left + right with same divider settings as other tabs
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(320)
        splitPane.setResizeWeight(0.0)
        panel.add(splitPane, BorderLayout.CENTER)

        # Action handlers
        def _onGetTimestamp(event):
            import time
            ms = int(time.time() * 1000)
            val = str(ms)
            tsOutputArea.setText(val)
            if self._tsAutoCopyChk.isSelected():
                from java.awt.datatransfer import StringSelection
                from java.awt import Toolkit
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(val), None)

        def _onCopyTimestamp(event):
            txt = tsOutputArea.getText().strip()
            if txt:
                from java.awt.datatransfer import StringSelection
                from java.awt import Toolkit
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(txt), None)

        tsBtn.addActionListener(_onGetTimestamp)
        copyBtn.addActionListener(_onCopyTimestamp)

        return panel

    def _buildGeneratorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # --- Left side: inputs ---
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        lgbc = GridBagConstraints()
        lgbc.insets = Insets(3, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.NORTHWEST
        lgbc.gridx = 0
        lgbc.weightx = 1.0
        lgbc.fill = GridBagConstraints.HORIZONTAL

        # Algorithm
        lgbc.gridy = 0
        lgbc.insets = Insets(3, 4, 3, 4)
        lbl = JLabel("Algorithm:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 1
        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        self._algoCombo = JComboBox(names)
        self._algoCombo.addActionListener(lambda e: self._updatePasscodeFieldState())
        leftPanel.add(self._algoCombo, lgbc)

        # Secret
        lgbc.gridy = 2
        lgbc.insets = Insets(10, 4, 3, 4)
        lbl = JLabel("Secret:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 3
        lgbc.insets = Insets(3, 4, 3, 4)
        self._passcodeField = JTextField()
        self._passcodeLabel = lbl
        leftPanel.add(self._passcodeField, lgbc)
        SwingUtilities.invokeLater(lambda: self._updatePasscodeFieldState())

        # Custom Data
        lgbc.gridy = 4
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Custom Data:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 5
        lgbc.insets = Insets(3, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.NORTHWEST
        self._customDataPanel = CustomDataPanel()
        leftPanel.add(self._customDataPanel, lgbc)

        # Keys Order
        lgbc.gridy = 6
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Sign Order (comma separated):")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 7
        lgbc.insets = Insets(3, 4, 3, 4)
        self._keysOrderField = JTextField()
        leftPanel.add(self._keysOrderField, lgbc)

        # Hash Field
        lgbc.gridy = 8
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        leftPanel.add(JLabel("Output Field:"), lgbc)

        lgbc.gridy = 9
        lgbc.insets = Insets(3, 4, 3, 4)
        self._mainHashFieldName = JTextField("hash")
        self._mainHashFieldName.setToolTipText("JSON key name where the output will be injected")
        leftPanel.add(self._mainHashFieldName, lgbc)

        # Body Format
        lgbc.gridy = 10
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Body Format:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 11
        lgbc.insets = Insets(3, 4, 3, 4)
        self._bodyFormatCombo = JComboBox(["JSON", "URL-encoded", "multipart/form-data"])
        leftPanel.add(self._bodyFormatCombo, lgbc)

        # Boundary (only relevant for multipart)
        lgbc.gridy = 12
        lgbc.insets = Insets(6, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Boundary (multipart only):")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 13
        lgbc.insets = Insets(3, 4, 3, 4)
        self._boundaryField = JTextField()
        self._boundaryField.setToolTipText("Paste the boundary value from Content-Type header (without leading --)")
        leftPanel.add(self._boundaryField, lgbc)

        # Generate button
        lgbc.gridy = 14
        lgbc.insets = Insets(20, 4, 4, 4)
        lgbc.anchor = GridBagConstraints.NORTHWEST
        self._generateBtn = JButton("Generate", actionPerformed=self._onGenerate)
        leftPanel.add(self._generateBtn, lgbc)

        # Spacer
        lgbc.gridy = 15
        lgbc.weighty = 1.0
        lgbc.insets = Insets(0, 0, 0, 0)
        leftPanel.add(JPanel(), lgbc)


        # -- Right side: text areas with label above each box --
        rightPanel = JPanel(GridBagLayout())
        rightPanel.setBorder(EmptyBorder(0, 0, 0, 0))
        gbc = GridBagConstraints()
        gbc.gridx   = 0
        gbc.weightx = 1.0
        gbc.fill    = GridBagConstraints.HORIZONTAL
        gbc.insets  = Insets(0, 0, 2, 0)

        # Payload label
        gbc.gridy  = 0; gbc.weighty = 0
        rightPanel.add(JLabel("Payload:"), gbc)

        # Payload text area
        gbc.gridy  = 1; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 8, 0)
        self._payloadArea = JTextArea(12, 40)
        self._payloadArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._payloadArea.setLineWrap(True)
        self._payloadArea.setWrapStyleWord(True)
        self._payloadArea.setText('{\n  "username": "user",\n  "request_time": "20260101010101"\n}')
        self._payloadArea.getDocument().addDocumentListener(
            PayloadDocumentListener(self._tryExtractKeys)
        )
        # Focus listener removed to prevent automatically rewriting float formatting (e.g. 12.00 to 12.0)
        payloadScroll = JScrollPane(self._payloadArea)
        payloadScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(payloadScroll, gbc)

        # Result Hash label
        gbc.gridy  = 2; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Result Hash:"), gbc)

        # Result Hash text area
        gbc.gridy  = 3; gbc.weighty = 0.2; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 8, 0)
        self._outputArea = JTextArea(3, 40)
        self._outputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._outputArea.setLineWrap(True)
        self._outputArea.setWrapStyleWord(True)
        self._outputArea.setEditable(False)
        outputScroll = JScrollPane(self._outputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(outputScroll, gbc)

        # Debug Output label
        gbc.gridy  = 4; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Debug Output:"), gbc)

        # Debug text area
        gbc.gridy  = 5; gbc.weighty = 0.6; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 0, 0)
        self._debugArea = JTextArea(6, 40)
        self._debugArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._debugArea.setForeground(Color(40, 40, 40))
        self._debugArea.setLineWrap(True)
        self._debugArea.setWrapStyleWord(True)
        self._debugArea.setEditable(False)
        debugScroll = JScrollPane(self._debugArea)
        debugScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(debugScroll, gbc)

        # Combine left + right
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(320)
        splitPane.setResizeWeight(0.0)
        panel.add(splitPane, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # Crypto Tab (AES-CBC-128 Encrypt / Decrypt)
    # -------------------------------------------------------------------------
    def _buildCryptoTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        monoFont  = Font("Monospaced", Font.PLAIN, 12)

        # ---- Left config panel ----
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        cgbc = GridBagConstraints()
        cgbc.insets  = Insets(4, 4, 4, 4)
        cgbc.anchor  = GridBagConstraints.NORTHWEST
        cgbc.gridx   = 0
        cgbc.weightx = 1.0
        cgbc.fill    = GridBagConstraints.HORIZONTAL

        # Mode
        cgbc.gridy = 0
        lbl = JLabel("Mode:")
        leftPanel.add(lbl, cgbc)

        cgbc.gridy = 1
        self._cryptoModeCombo = JComboBox(["Encrypt", "Decrypt"])
        leftPanel.add(self._cryptoModeCombo, cgbc)

        # Algorithm (AES-CBC-128 only for now)
        cgbc.gridy = 2
        cgbc.insets = Insets(10, 4, 4, 4)
        lbl = JLabel("Algorithm:")
        leftPanel.add(lbl, cgbc)

        cgbc.gridy = 3
        cgbc.insets = Insets(4, 4, 4, 4)
        crypto_names = self.crypto_snippet_manager.get_all_names()
        if not crypto_names:
            crypto_names = ["(no algorithms -- add via Crypto Editor)"]
        self._cryptoAlgoCombo = JComboBox(crypto_names)
        # Update Key/IV fields when algorithm changes
        self._cryptoAlgoCombo.addActionListener(lambda e: self._updateCryptoFieldState())
        leftPanel.add(self._cryptoAlgoCombo, cgbc)

        # Key
        cgbc.gridy = 4
        cgbc.insets = Insets(10, 4, 4, 4)
        leftPanel.add(JLabel("Key:"), cgbc)

        cgbc.gridy = 5
        cgbc.insets = Insets(4, 4, 4, 4)
        self._cryptoKeyField = JTextField()
        leftPanel.add(self._cryptoKeyField, cgbc)

        # IV
        cgbc.gridy = 6
        cgbc.insets = Insets(10, 4, 4, 4)
        leftPanel.add(JLabel("IV:"), cgbc)

        cgbc.gridy = 7
        cgbc.insets = Insets(4, 4, 4, 4)
        self._cryptoIvField = JTextField()
        leftPanel.add(self._cryptoIvField, cgbc)

        # Field
        cgbc.gridy = 8
        cgbc.insets = Insets(10, 4, 4, 4)
        leftPanel.add(JLabel("Field:"), cgbc)

        cgbc.gridy = 9
        cgbc.insets = Insets(4, 4, 4, 4)
        self._mainCryptoField = JTextField("data")
        self._mainCryptoField.setToolTipText("JSON key to read input from / write output to")
        leftPanel.add(self._mainCryptoField, cgbc)

        # Run button
        cgbc.gridy = 10
        cgbc.insets = Insets(20, 4, 4, 4)
        self._cryptoRunBtn = JButton("Run Crypto", actionPerformed=self._onCryptoRun)
        leftPanel.add(self._cryptoRunBtn, cgbc)

        # Spacer
        cgbc.gridy = 11
        cgbc.weighty = 1.0
        cgbc.insets  = Insets(0, 0, 0, 0)
        leftPanel.add(JPanel(), cgbc)

        # ---- Right: input + output text areas ----
        rightPanel = JPanel(GridBagLayout())
        rgbc = GridBagConstraints()
        rgbc.fill    = GridBagConstraints.BOTH
        rgbc.insets  = Insets(2, 0, 2, 0)
        rgbc.gridx   = 0
        rgbc.weightx = 1.0

        # Input label
        rgbc.gridy  = 0
        rgbc.weighty = 0
        rgbc.fill   = GridBagConstraints.HORIZONTAL
        inputLbl    = JLabel("Input (plaintext for Encrypt, Base64 for Decrypt):")
        rightPanel.add(inputLbl, rgbc)

        # Input text area
        rgbc.gridy  = 1
        rgbc.weighty = 1.0
        rgbc.fill   = GridBagConstraints.BOTH
        self._cryptoInputArea = JTextArea(10, 40)
        self._cryptoInputArea.setLineWrap(True)
        self._cryptoInputArea.setWrapStyleWord(True)
        inputScroll = JScrollPane(self._cryptoInputArea)
        inputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(inputScroll, rgbc)

        # Output label
        rgbc.gridy  = 2
        rgbc.weighty = 0
        rgbc.fill   = GridBagConstraints.HORIZONTAL
        outputLbl   = JLabel("Output:")
        rightPanel.add(outputLbl, rgbc)

        # Output text area
        rgbc.gridy  = 3
        rgbc.weighty = 0.4
        rgbc.fill   = GridBagConstraints.BOTH
        self._cryptoOutputArea = JTextArea(4, 40)
        self._cryptoOutputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoOutputArea.setEditable(False)
        self._cryptoOutputArea.setLineWrap(True)
        self._cryptoOutputArea.setWrapStyleWord(True)
        outputScroll = JScrollPane(self._cryptoOutputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(outputScroll, rgbc)

        # Combine left + right
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(320)
        splitPane.setResizeWeight(0.0)
        panel.add(splitPane, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # UI State Helpers: requires_key / requires_iv field visibility
    # -------------------------------------------------------------------------
    def _updatePasscodeFieldState(self):
        """Dim/enable the Secret field in the Hash tab based on requires_key flag."""
        try:
            name    = str(self._algoCombo.getSelectedItem())
            snippet = self.snippet_manager.get_snippet(name)
            needs   = True  # default: key required
            if snippet:
                needs = snippet.get("requires_key", True)
            gray = Color(160, 160, 160)
            black = Color(0, 0, 0)
            if needs:
                self._passcodeField.setEditable(True)
                self._passcodeField.setForeground(black)
                self._passcodeField.setToolTipText(None)
                self._passcodeLabel.setForeground(black)
            else:
                self._passcodeField.setEditable(False)
                self._passcodeField.setForeground(gray)
                self._passcodeField.setToolTipText("Not used for " + name)
                self._passcodeField.setText("")
                self._passcodeLabel.setForeground(gray)
        except Exception:
            pass

    def _updateCryptoFieldState(self):
        """Show/dim Key and IV fields based on the selected crypto algo's flags."""
        try:
            name     = str(self._cryptoAlgoCombo.getSelectedItem())
            needs_k  = self.crypto_snippet_manager.requires_key(name)
            needs_iv = self.crypto_snippet_manager.requires_iv(name)
            gray  = Color(160, 160, 160)
            black = Color(0, 0, 0)
            self._cryptoKeyField.setEditable(needs_k)
            self._cryptoKeyField.setForeground(black if needs_k else gray)
            self._cryptoKeyField.setToolTipText(
                None if needs_k else "Key not required for " + name
            )
            self._cryptoIvField.setEditable(needs_iv)
            self._cryptoIvField.setForeground(black if needs_iv else gray)
            self._cryptoIvField.setToolTipText(
                None if needs_iv else "IV not required for " + name
            )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # AppSetting Actions
    # -------------------------------------------------------------------------
    def _onSettingSelected(self):
        """Load selected app setting into Hash + Crypto main tab fields."""
        try:
            name = str(self._settingCombo.getSelectedItem())
            if name == "(none)":
                return
            app = self.app_setting_manager.get_app(name)
            if not app:
                return
            if app.get("algorithm"):
                self._algoCombo.setSelectedItem(app["algorithm"])
            if "secret" in app:
                self._passcodeField.setText(app["secret"])
            if app.get("custom_data"):
                self._customDataPanel.setPairs(app["custom_data"])
            if "hash_field" in app:
                self._mainHashFieldName.setText(app["hash_field"])
            # keys_order: show first endpoint's value if available
            endpoints = app.get("endpoints", {})
            if endpoints:
                first_ep = list(endpoints.values())[0]
                self._keysOrderField.setText(first_ep.get("keys_order", ""))
                if "custom_data" in first_ep:
                    self._customDataPanel.setPairs(first_ep["custom_data"])
            # Crypto config
            c = app.get("crypto", {})
            if c.get("mode"):
                self._cryptoModeCombo.setSelectedItem(c["mode"])
            if c.get("algorithm"):
                self._cryptoAlgoCombo.setSelectedItem(c["algorithm"])
            if "key" in c:
                self._cryptoKeyField.setText(c["key"])
            if "iv" in c:
                self._cryptoIvField.setText(c["iv"])
            if "field" in c:
                self._mainCryptoField.setText(c["field"])
        except Exception as e:
            print("[CipherKit] Setting load error: %s" % str(e))

    def _onSaveNewSetting(self, event=None):
        """Save current config as a new app-level setting."""
        name = JOptionPane.showInputDialog(
            self._mainPanel, "App setting name:", "Save Setting",
            JOptionPane.PLAIN_MESSAGE, None, None, ""
        )
        if not name or not str(name).strip():
            return
        name = str(name).strip()
        app_data = self._getAppSettingData()
        self.app_setting_manager.save_app(name, app_data)
        self._refreshSettingCombo()
        self._settingCombo.setSelectedItem(name)
        self._refreshSettingSummary()
        print("[CipherKit] AppSetting saved: %s" % name)

    def _onDeleteSetting(self, event=None):
        """Delete the selected app setting."""
        name = str(self._settingCombo.getSelectedItem())
        if name == "(none)":
            return
        confirm = JOptionPane.showConfirmDialog(
            self._mainPanel, "Delete app setting '%s' and all its endpoints?" % name,
            "Delete Setting", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.app_setting_manager.delete_app(name)
            self._refreshSettingCombo()
            self._refreshSettingSummary()
            print("[CipherKit] AppSetting deleted: %s" % name)

    def _onUpdateSetting(self, event=None):
        """Update the selected app setting with current config."""
        name = str(self._settingCombo.getSelectedItem())
        if name == "(none)":
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select an app setting first.", "Update Setting",
                JOptionPane.INFORMATION_MESSAGE)
            return
        app_data = self._getAppSettingData()
        self.app_setting_manager.save_app(name, app_data)
        self._refreshSettingSummary()
        print("[CipherKit] AppSetting updated: %s" % name)

    def _getAppSettingData(self):
        """Helper to collect current UI fields for saving to AppSetting."""
        return {
            "algorithm":   str(self._algoCombo.getSelectedItem()),
            "secret":      self._passcodeField.getText(),
            "custom_data": self._customDataPanel.getPairs(),
            "hash_field":  self._mainHashFieldName.getText().strip() or "hash",
            "crypto": {
                "mode":      str(self._cryptoModeCombo.getSelectedItem()),
                "algorithm": str(self._cryptoAlgoCombo.getSelectedItem()),
                "key":       self._cryptoKeyField.getText(),
                "iv":        self._cryptoIvField.getText(),
                "field":     self._mainCryptoField.getText().strip() or "data",
            },
        }

    def _onSettingComboChange(self, event=None):
        self._refreshSettingSummary()

    def _refreshSettingCombo(self):
        """Refresh the main setting combo box with current app names."""
        HashGenEditorTab._refill_setting_combo(
            self._settingCombo, self.app_setting_manager.get_all_names()
        )

    def _refreshSettingSummary(self):
        """Refresh the AppSetting tab summary text area with the selected app's config."""
        try:
            name = str(self._settingCombo.getSelectedItem())
            if name == "(none)":
                self._settingSummaryArea.setText("(no setting selected)")
                return
            app = self.app_setting_manager.get_app(name)
            if not app:
                self._settingSummaryArea.setText("(setting not found)")
                return
            lines = []
            lines.append("App Setting : %s" % name)
            lines.append("")
            lines.append("Shared Config")
            lines.append("-" * 44)
            lines.append("  Algorithm : %s" % app.get("algorithm", ""))
            lines.append("  Secret    : %s" % app.get("secret", ""))
            lines.append("  Hash Field: %s" % app.get("hash_field", ""))
            custom_data = app.get("custom_data", {})
            if custom_data:
                custom_str = ", ".join("%s=%s" % (k, v) for k, v in custom_data.items())
                lines.append("  Custom Data: %s" % custom_str)
            c = app.get("crypto", {})
            if c:
                lines.append("")
                lines.append("  Crypto")
                lines.append("    Algorithm: %s" % c.get("algorithm", ""))
                lines.append("    Key      : %s" % c.get("key", ""))
                lines.append("    IV       : %s" % c.get("iv", ""))
                lines.append("    Field    : %s" % c.get("field", ""))
            endpoints = app.get("endpoints", {})
            if endpoints:
                lines.append("")
                lines.append("Endpoints")
                lines.append("-" * 44)
                for pat, ep in endpoints.items():
                    custom_str = ""
                    if "custom_data" in ep and ep["custom_data"]:
                        custom_str = " [Custom: %s]" % ", ".join("%s=%s" % (k, v) for k, v in ep["custom_data"].items())
                    lines.append("  %-30s  %s%s" % (pat, ep.get("keys_order", ""), custom_str))
            else:
                lines.append("")
                lines.append("No endpoints saved yet.")
            self._settingSummaryArea.setText("\n".join(lines))
            self._settingSummaryArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] AppSetting summary error: %s" % str(e))

    # -------------------------------------------------------------------------
    # Crypto Editor Tab (add/edit/delete crypto snippet algorithms)
    # -------------------------------------------------------------------------
    def _buildCryptoEditorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Top bar: name + buttons
        topPanel = JPanel(BorderLayout(8, 0))
        topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        self._cryptoSnippetNameField = JTextField()
        self._cryptoSnippetNameField.setBorder(
            _roundedCompound(radius=8, padding=6)
        )
        self._cryptoSnippetNameField.setToolTipText("Algorithm name (e.g. AES-CBC-128, ChaCha20)")
        topPanel.add(self._cryptoSnippetNameField, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        loadBtn   = JButton("Load",   actionPerformed=self._onLoadCryptoSnippet)
        saveBtn   = JButton("Save",   actionPerformed=self._onSaveCryptoSnippet)
        deleteBtn = JButton("Delete", actionPerformed=self._onDeleteCryptoSnippet)
        btnPanel.add(loadBtn)
        btnPanel.add(saveBtn)
        btnPanel.add(deleteBtn)
        topPanel.add(btnPanel, BorderLayout.EAST)
        panel.add(topPanel, BorderLayout.NORTH)

        # Info label
        infoLabel = JLabel(
            "Define encrypt(plaintext, key, iv) and decrypt(ciphertext_b64, key, iv) -- "
            "both must return a string. Use javax.crypto, base64, json as needed."
        )
        infoLabel.setForeground(Color(130, 130, 130))

        # Encrypt code area
        encTemplate = (
            "def encrypt(plaintext, key, iv):\n"
            "    # plaintext : str, key : str, iv : str (may be empty)\n"
            "    # Must return a string (e.g. Base64 ciphertext)\n"
            "    from javax.crypto import Cipher\n"
            "    from javax.crypto.spec import SecretKeySpec, IvParameterSpec\n"
            "    import base64\n"
            "    return \"result\""
        )
        self._cryptoEncArea = JTextArea(10, 60)
        self._cryptoEncArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoEncArea.setTabSize(4)
        self._cryptoEncArea.setText(encTemplate)
        encScroll = JScrollPane(self._cryptoEncArea)
        encScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

        # Decrypt code area
        decTemplate = (
            "def decrypt(ciphertext_b64, key, iv):\n"
            "    # ciphertext_b64 : str (Base64), key : str, iv : str (may be empty)\n"
            "    # Must return a string (plaintext)\n"
            "    from javax.crypto import Cipher\n"
            "    from javax.crypto.spec import SecretKeySpec, IvParameterSpec\n"
            "    import base64\n"
            "    return \"result\""
        )
        self._cryptoDecArea = JTextArea(10, 60)
        self._cryptoDecArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoDecArea.setTabSize(4)
        self._cryptoDecArea.setText(decTemplate)
        decScroll = JScrollPane(self._cryptoDecArea)
        decScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

        encWrap = JPanel(BorderLayout(0, 2))
        encWrap.add(JLabel("Encrypt Function:"), BorderLayout.NORTH)
        encWrap.add(encScroll, BorderLayout.CENTER)

        decWrap = JPanel(BorderLayout(0, 2))
        decWrap.add(JLabel("Decrypt Function:"), BorderLayout.NORTH)
        decWrap.add(decScroll, BorderLayout.CENTER)

        codePane = JSplitPane(JSplitPane.VERTICAL_SPLIT, encWrap, decWrap)
        codePane.setResizeWeight(0.5)

        centerPanel = JPanel(BorderLayout(0, 6))
        centerPanel.add(infoLabel, BorderLayout.NORTH)
        centerPanel.add(codePane, BorderLayout.CENTER)
        panel.add(centerPanel, BorderLayout.CENTER)
        return panel

    # -------------------------------------------------------------------------
    # Snippet Editor Tab
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Key Order Finder Tab
    # -------------------------------------------------------------------------
    def _buildKeyFinderTab(self):
        """
        Reverse-engineer key concatenation order.
        Given a JSON / form-data body and a known concatenated string,
        find which permutation of the field values produces that string.

        Layout:
          LEFT  - Body Format, Request Body (large), Additional Values, Parse Body button
          RIGHT - Parsed Fields, Known String, Find Key Order, Results
        """
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # ---- LEFT: Body Format, Request Body, Additional Values, Parse button ----
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(_roundedCompound(radius=8, padding=10))

        lgbc = GridBagConstraints()
        lgbc.gridx = 0; lgbc.weightx = 1.0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(4, 4, 4, 4)

        # Body format dropdown
        lgbc.gridy = 0; lgbc.weighty = 0
        fmtRow = JPanel(BorderLayout(0, 2))
        fmtRow.add(JLabel("Body Format:"), BorderLayout.NORTH)
        self._kfFormatCombo = JComboBox(["JSON", "Form Data"])
        fmtRow.add(self._kfFormatCombo, BorderLayout.CENTER)
        leftPanel.add(fmtRow, lgbc)

        # Request body textarea (large)
        lgbc.gridy = 1; lgbc.insets = Insets(8, 4, 2, 4)
        leftPanel.add(JLabel("Request Body (paste here):"), lgbc)

        lgbc.gridy = 2; lgbc.weighty = 1.0; lgbc.fill = GridBagConstraints.BOTH
        lgbc.insets = Insets(2, 4, 8, 4)
        self._kfBodyArea = JTextArea(12, 30)
        self._kfBodyArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfBodyArea.setLineWrap(True)
        self._kfBodyArea.setWrapStyleWord(True)
        bodyScroll = JScrollPane(self._kfBodyArea)
        bodyScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        leftPanel.add(bodyScroll, lgbc)

        # Additional values (N-06: CompactCustomDataPanel replaces free-text JTextArea)
        lgbc.gridy = 3; lgbc.weighty = 0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(0, 4, 2, 4)
        leftPanel.add(JLabel("Extra Fields (key: value):"), lgbc)

        lgbc.gridy = 4; lgbc.weighty = 0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(2, 4, 8, 4)
        self._kfAdditionalPanel = CompactCustomDataPanel()
        self._kfAdditionalPanel.setToolTipText("Extra fields not in the request body, e.g. API: A2345@#$...")
        leftPanel.add(self._kfAdditionalPanel, lgbc)

        # Parse button
        lgbc.gridy = 5; lgbc.weighty = 0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(0, 4, 4, 4)
        parseBtn = JButton("Parse Body", actionPerformed=self._onParseKeyFinderBody)
        parseBtn.setToolTipText("Parse the request body and populate Parsed Fields on the right")
        leftPanel.add(parseBtn, lgbc)

        # ---- RIGHT: Parsed Fields, Known String, Find, Results ----
        rightPanel = JPanel(GridBagLayout())
        rgbc = GridBagConstraints()
        rgbc.gridx = 0; rgbc.weightx = 1.0; rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.insets = Insets(0, 0, 2, 0)

        # Parsed fields (editable)
        rgbc.gridy = 0; rgbc.weighty = 0
        rightPanel.add(JLabel("Parsed Fields (key: value):"), rgbc)

        rgbc.gridy = 1; rgbc.weighty = 0.4; rgbc.fill = GridBagConstraints.BOTH
        rgbc.insets = Insets(2, 0, 8, 0)
        self._kfParsedArea = JTextArea(8, 28)
        self._kfParsedArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfParsedArea.setEditable(True)
        self._kfParsedArea.setLineWrap(True)
        self._kfParsedArea.setToolTipText("Auto-filled by Parse Body, or edit manually")
        parsedScroll = JScrollPane(self._kfParsedArea)
        parsedScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(parsedScroll, rgbc)

        # Known concatenated string (bigger box)
        rgbc.gridy = 2; rgbc.weighty = 0; rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Known Concatenated String (the hash input):"), rgbc)

        rgbc.gridy = 3; rgbc.weighty = 0.2; rgbc.fill = GridBagConstraints.BOTH
        rgbc.insets = Insets(2, 0, 8, 0)
        self._kfKnownArea = JTextArea(5, 28)
        self._kfKnownArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfKnownArea.setLineWrap(True)
        self._kfKnownArea.setWrapStyleWord(True)
        knownScroll = JScrollPane(self._kfKnownArea)
        knownScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(knownScroll, rgbc)

        # Find button
        rgbc.gridy = 4; rgbc.weighty = 0; rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.insets = Insets(0, 0, 8, 0)
        findBtn = JButton("Find Key Order", actionPerformed=self._onFindOrder)
        rightPanel.add(findBtn, rgbc)

        # Results
        rgbc.gridy = 5; rgbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Results:"), rgbc)

        rgbc.gridy = 6; rgbc.weighty = 0.4; rgbc.fill = GridBagConstraints.BOTH
        rgbc.insets = Insets(2, 0, 0, 0)
        self._kfResultArea = JTextArea(8, 40)
        self._kfResultArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfResultArea.setEditable(False)
        self._kfResultArea.setLineWrap(True)
        self._kfResultArea.setWrapStyleWord(True)
        resultScroll = JScrollPane(self._kfResultArea)
        resultScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(resultScroll, rgbc)

        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(420)
        splitPane.setResizeWeight(0.45)
        panel.add(splitPane, BorderLayout.CENTER)
        return panel

    def _onParseKeyFinderBody(self, event=None):
        """Parse the body textarea and populate the Parsed Fields textarea."""
        body = self._kfBodyArea.getText().strip()
        fmt  = str(self._kfFormatCombo.getSelectedItem())
        try:
            pairs = self._kfParseBody(body, fmt)
            if not pairs:
                self._kfParsedArea.setText("(no fields found)")
                return
            lines = ["%s: %s" % (k, v) for k, v in pairs.items()]
            self._kfParsedArea.setText("\n".join(lines))
        except Exception as e:
            self._kfParsedArea.setText("Parse error: %s" % str(e))

    def _kfParseBody(self, body, fmt):
        """Return OrderedDict-like list of (key, value) from JSON or form data."""
        from collections import OrderedDict
        pairs = OrderedDict()
        if fmt == "JSON":
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("JSON is not an object")
            for k, v in data.items():
                pairs[str(k)] = str(v)
        else:  # Form Data
            for part in body.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    pairs[k.strip()] = v.strip()
        return pairs

    def _kfReadParsedFields(self):
        """Read the manually-editable Parsed Fields and Additional Values areas back into an OrderedDict."""
        from collections import OrderedDict
        pairs = OrderedDict()
        
        # Read from Parsed Fields
        text1 = self._kfParsedArea.getText().strip()
        for line in text1.splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                pairs[k.strip()] = v.strip()
                
        # Read from Extra Fields panel (N-06: CompactCustomDataPanel)
        for k, v in self._kfAdditionalPanel.getPairs().items():
            if k:
                pairs[k] = v
                
        return pairs

    def _onFindOrder(self, event=None):
        """
        Bug-2 fix: brute-force runs in a background thread to avoid freezing Burp.
        UI updates are dispatched via SwingUtilities.invokeLater.
        """
        known = str(self._kfKnownArea.getText().strip())
        sep   = ""

        if not known:
            self._kfResultArea.setText("Please enter the known concatenated string.")
            return

        pairs = self._kfReadParsedFields()
        if not pairs:
            self._kfResultArea.setText("No fields found. Paste a body and click Parse Body first.")
            return

        self._kfResultArea.setText("Searching... (running in background)")

        _outer = self
        _pairs_snap = dict(pairs)
        _known_snap = known
        _sep_snap   = sep

        import threading as _threading

        def _run():
            keys = list(_pairs_snap.keys())
            values = {k: str(v) for k, v in _pairs_snap.items()}
            matches = []
            total_visited = [0]

            def dfs(current_perm, remaining_keys, remaining_known):
                total_visited[0] += 1
                if len(matches) >= 100 or total_visited[0] >= 10000:
                    return
                if not remaining_known:
                    if current_perm:
                        matches.append(current_perm)
                    return
                for k in remaining_keys:
                    val = values[k]
                    if not val:
                        continue
                    if remaining_known.startswith(val):
                        next_keys = [x for x in remaining_keys if x != k]
                        dfs(current_perm + (k,), next_keys, remaining_known[len(val):])

            dfs((), keys, _known_snap)

            lines = []
            lines.append("Known string : '%s'" % _known_snap)
            lines.append("Fields tried : %s" % ", ".join(keys))
            lines.append("States visited: %d" % total_visited[0])
            lines.append("-" * 50)

            if not matches:
                lines.append("No match found.")
                lines.append("")
                lines.append("Tip: check if the separator or values are correct.")
                lines.append("Values used:")
                for k, v in values.items():
                    lines.append("  %s = '%s'" % (k, str(v)))
            else:
                lines.append("%d match(es) found:" % len(matches))
                lines.append("")
                for i, perm in enumerate(matches, 1):
                    key_order_str = ", ".join(perm)
                    concat_show   = _sep_snap.join(str(values[k]) for k in perm)
                    lines.append("Match #%d:" % i)
                    lines.append("  Key order  : %s" % key_order_str)
                    lines.append("  Concat     : '%s'" % concat_show)
                    lines.append("")
                if len(matches) >= 100 or total_visited[0] >= 10000:
                    lines.append("(Note: search was capped at 100 matches to optimize performance)")
                    lines.append("")
                lines.append("Copy the key order above into the Hash tab's 'Keys Order' field.")

            result_text = "\n".join(lines)
            SwingUtilities.invokeLater(lambda: _outer._kfResultArea.setText(result_text))

        t = _threading.Thread(target=_run)
        t.setDaemon(True)
        t.start()


    # -------------------------------------------------------------------------
    # Snippet Editor Tab
    # -------------------------------------------------------------------------
    def _buildEditorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Top bar: name + buttons
        topPanel = JPanel(BorderLayout(8, 0))
        topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        self._snippetNameField = JTextField()
        self._snippetNameField.setBorder(
            _roundedCompound(radius=8, padding=6)
        )
        self._snippetNameField.putClientProperty("JTextField.placeholderText", "e.g. My HMAC-SHA256")
        topPanel.add(self._snippetNameField, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        loadBtn = JButton("Load", actionPerformed=self._onLoadSnippet)
        saveBtn = JButton("Save", actionPerformed=self._onSaveSnippet)
        deleteBtn = JButton("Delete", actionPerformed=self._onDeleteSnippet)
        btnPanel.add(loadBtn)
        btnPanel.add(saveBtn)
        btnPanel.add(deleteBtn)
        topPanel.add(btnPanel, BorderLayout.EAST)

        panel.add(topPanel, BorderLayout.NORTH)

        # Info label
        infoLabel = JLabel("Python code must define: generate(payload, passcode, custom_data=None, key_order=None)")
        infoLabel.setForeground(Color(130, 130, 130))

        # Code editor area
        self._codeArea = JTextArea(20, 60)
        self._codeArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._codeArea.setTabSize(4)
        self._codeArea.setLineWrap(False)

        default_template = (
            'def generate(payload, passcode, custom_data=None, key_order=None):\n'
            '    import hashlib\n'
            '    # payload = merged dict of Custom Data fields + request body JSON\n'
            '    # custom_data = dict {key_name: value} from Custom Data fields\n'
            '    # key_order = list of key names to sign (from Keys Order field)\n'
            '    \n'
            '    debug_log = "--- Debug Info ---\\n"\n'
            '    debug_log += "Keys received: " + str(list(payload.keys())) + "\\n"\n'
            '    \n'
            '    # You can return just the hash string, OR a tuple (hash, debug_output)\n'
            '    return "hash_result", debug_log'
        )
        self._codeArea.setText(default_template)

        codeScroll = JScrollPane(self._codeArea)
        codeScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

        centerPanel = JPanel(BorderLayout(0, 6))
        centerPanel.add(infoLabel, BorderLayout.NORTH)
        centerPanel.add(codeScroll, BorderLayout.CENTER)
        panel.add(centerPanel, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # UI Helper
    # -------------------------------------------------------------------------
    def _createLabel(self, text):
        label = JLabel(text)
        label.setAlignmentX(Component.LEFT_ALIGNMENT)
        return label

    # -------------------------------------------------------------------------
    # Actions: Crypto
    # -------------------------------------------------------------------------
    def _onCryptoRun(self, event=None):
        """Encrypt or decrypt using the selected crypto snippet algorithm."""
        try:
            algo      = str(self._cryptoAlgoCombo.getSelectedItem())
            mode      = str(self._cryptoModeCombo.getSelectedItem())
            key       = self._cryptoKeyField.getText()
            iv        = self._cryptoIvField.getText().strip()
            input_txt = self._cryptoInputArea.getText().strip()

            snippet = self.crypto_snippet_manager.get_snippet(algo)
            if not snippet:
                self._cryptoOutputArea.setText("Error: Algorithm '%s' not found." % algo)
                return

            needs_key = self.crypto_snippet_manager.requires_key(algo)
            if needs_key and not key:
                self._cryptoOutputArea.setText("Error: Key is required for %s." % algo)
                return
            if not input_txt:
                self._cryptoOutputArea.setText("Error: Input is empty.")
                return

            result = CryptoSnippetEngine.execute(snippet, mode, input_txt, key, iv)
            self._cryptoOutputArea.setText(str(result))

        except Exception as e:
            self._cryptoOutputArea.setText("Error: %s" % str(e))

    # -------------------------------------------------------------------------
    # Actions: Generator
    # -------------------------------------------------------------------------
    def _onGenerate(self, event=None):
        name = self._algoCombo.getSelectedItem()
        if not name:
            self._outputArea.setText("Error: No algorithm selected.")
            self._debugArea.setText("")
            return

        snippet = self.snippet_manager.get_snippet(str(name))
        if not snippet:
            self._outputArea.setText("Error: Snippet '%s' not found." % name)
            self._debugArea.setText("")
            return

        try:
            payload_str = self._payloadArea.getText().strip()

            # Build content_type from user-selected format + boundary
            fmt = str(self._bodyFormatCombo.getSelectedItem())
            if fmt == "multipart/form-data":
                boundary = self._boundaryField.getText().strip()
                if boundary:
                    content_type = "multipart/form-data; boundary=" + boundary
                else:
                    content_type = "multipart/form-data"
            elif fmt == "URL-encoded":
                content_type = "application/x-www-form-urlencoded"
            else:
                content_type = "application/json"

            payload = parse_body(payload_str, content_type)
            if not payload:
                self._outputArea.setText("Error: Payload could not be parsed or is empty.")
                self._debugArea.setText("")
                return
            passcode = self._passcodeField.getText()
            custom_data = self._customDataPanel.getPairs()

            keys_str = self._keysOrderField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            result, debug_log = CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, custom_data, key_order
            )

            result_str = str(result)
            if not result_str.startswith("Error") and self._globalUppercaseHashChk.isSelected():
                result_str = result_str.upper()

            self._outputArea.setText(result_str)
            self._debugArea.setText(str(debug_log))

        except Exception as e:
            self._outputArea.setText("Error: %s" % str(e))
            self._debugArea.setText(traceback.format_exc())

    def _tryExtractKeys(self):
        """Auto-extract keys from payload using the selected body format."""
        try:
            payload_str = self._payloadArea.getText().strip()
            if not payload_str:
                return
            # Use selected format if available
            try:
                fmt = str(self._bodyFormatCombo.getSelectedItem())
                if fmt == "multipart/form-data":
                    boundary = self._boundaryField.getText().strip()
                    ct = "multipart/form-data; boundary=" + boundary if boundary else "multipart/form-data"
                elif fmt == "URL-encoded":
                    ct = "application/x-www-form-urlencoded"
                else:
                    ct = "application/json"
            except:
                ct = ""
            data = parse_body(payload_str, ct)
            if isinstance(data, dict) and data:
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysOrderField.getText().strip()
                if current != new_keys_str:
                    self._keysOrderField.setText(new_keys_str)
        except:
            pass

    def _tryFormatJson(self):
        try:
            payload_str = self._payloadArea.getText().strip()
            if not payload_str:
                return
            data = json.loads(payload_str)
            formatted = json.dumps(data, indent=2)
            if formatted != payload_str:
                self._payloadArea.setText(formatted)
        except:
            pass

    # -------------------------------------------------------------------------
    # Actions: Snippet Editor
    # -------------------------------------------------------------------------
    def _onSaveSnippet(self, event=None):
        name = self._snippetNameField.getText().strip()
        snippet_code = self._codeArea.getText().strip()

        if not name:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "Please enter a snippet name.",
                "CipherKit - Save Error",
                JOptionPane.WARNING_MESSAGE
            )
            return

        # Improvement-6: syntax-check before saving so runtime crashes are avoided
        try:
            compile(snippet_code, "<snippet:%s>" % name, "exec")
        except SyntaxError as se:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "Syntax error on line %d:\n%s" % (se.lineno or 0, str(se.msg)),
                "CipherKit - Syntax Error",
                JOptionPane.ERROR_MESSAGE
            )
            return

        self.snippet_manager.update_snippet(name, snippet_code)
        self._refreshAlgoList()
        JOptionPane.showMessageDialog(
            self._mainPanel,
            "Snippet '%s' saved successfully." % name,
            "CipherKit",
            JOptionPane.INFORMATION_MESSAGE
        )
        print("[*] Snippet saved: %s" % name)

    def _onLoadSnippet(self, event=None):
        names = self.snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "No snippets available.",
                "CipherKit - Load",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        selected = JOptionPane.showInputDialog(
            self._mainPanel,
            "Select a snippet to load:",
            "CipherKit - Load Snippet",
            JOptionPane.PLAIN_MESSAGE,
            None,
            names,
            names[0]
        )

        if selected:
            snippet = self.snippet_manager.get_snippet(str(selected))
            if snippet:
                self._snippetNameField.setText(str(selected))
                self._codeArea.setText(snippet["code"])
                print("[*] Snippet loaded: %s" % selected)

    def _onDeleteSnippet(self, event=None):
        names = self.snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "No snippets to delete.",
                "CipherKit",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        selected = JOptionPane.showInputDialog(
            self._mainPanel,
            "Select a snippet to delete:",
            "CipherKit - Delete Snippet",
            JOptionPane.WARNING_MESSAGE,
            None,
            names,
            names[0]
        )

        if selected:
            confirm = JOptionPane.showConfirmDialog(
                self._mainPanel,
                "Are you sure you want to delete '%s'?" % selected,
                "CipherKit - Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                self.snippet_manager.delete_snippet(str(selected))
                self._refreshAlgoList()
                print("[*] Snippet deleted: %s" % selected)

    def _refreshAlgoList(self):
        self._algoCombo.removeAllItems()
        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        for name in names:
            self._algoCombo.addItem(name)
        self._updatePasscodeFieldState()

    def _refreshCryptoAlgoList(self):
        self._cryptoAlgoCombo.removeAllItems()
        names = self.crypto_snippet_manager.get_all_names()
        if not names:
            self._cryptoAlgoCombo.addItem("(no algorithms -- add via Crypto Editor)")
        else:
            for name in names:
                self._cryptoAlgoCombo.addItem(name)
        self._updateCryptoFieldState()

    # -------------------------------------------------------------------------
    # Actions: Crypto Editor
    # -------------------------------------------------------------------------
    def _onSaveCryptoSnippet(self, event=None):
        name = self._cryptoSnippetNameField.getText().strip()
        enc  = self._cryptoEncArea.getText().strip()
        dec  = self._cryptoDecArea.getText().strip()
        if not name:
            JOptionPane.showMessageDialog(
                self._mainPanel, "Please enter an algorithm name.",
                "CipherKit - Save Error", JOptionPane.WARNING_MESSAGE
            )
            return
        # Improvement-6: syntax-check both functions before saving
        for label, src in (("encrypt", enc), ("decrypt", dec)):
            try:
                compile(src, "<crypto_snippet:%s:%s>" % (name, label), "exec")
            except SyntaxError as se:
                JOptionPane.showMessageDialog(
                    self._mainPanel,
                    "%s function syntax error on line %d:\n%s" % (label, se.lineno or 0, str(se.msg)),
                    "CipherKit - Syntax Error",
                    JOptionPane.ERROR_MESSAGE
                )
                return
        self.crypto_snippet_manager.update_snippet(name, enc, dec)
        self._refreshCryptoAlgoList()
        JOptionPane.showMessageDialog(
            self._mainPanel, "Crypto snippet '%s' saved." % name,
            "CipherKit", JOptionPane.INFORMATION_MESSAGE
        )
        print("[*] Crypto snippet saved: %s" % name)

    def _onLoadCryptoSnippet(self, event=None):
        names = self.crypto_snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel, "No crypto snippets available.",
                "CipherKit - Load", JOptionPane.INFORMATION_MESSAGE
            )
            return
        selected = JOptionPane.showInputDialog(
            self._mainPanel, "Select a crypto snippet to load:",
            "CipherKit - Load Crypto Snippet", JOptionPane.PLAIN_MESSAGE,
            None, names, names[0]
        )
        if selected:
            snippet = self.crypto_snippet_manager.get_snippet(str(selected))
            if snippet:
                self._cryptoSnippetNameField.setText(str(selected))
                self._cryptoEncArea.setText(snippet.get("encrypt_code", ""))
                self._cryptoDecArea.setText(snippet.get("decrypt_code", ""))
                print("[*] Crypto snippet loaded: %s" % selected)

    def _onDeleteCryptoSnippet(self, event=None):
        names = self.crypto_snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel, "No crypto snippets to delete.",
                "CipherKit", JOptionPane.INFORMATION_MESSAGE
            )
            return
        selected = JOptionPane.showInputDialog(
            self._mainPanel, "Select a crypto snippet to delete:",
            "CipherKit - Delete Crypto Snippet", JOptionPane.WARNING_MESSAGE,
            None, names, names[0]
        )
        if selected:
            confirm = JOptionPane.showConfirmDialog(
                self._mainPanel, "Delete '%s'?" % selected,
                "CipherKit - Confirm Delete", JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                self.crypto_snippet_manager.delete_snippet(str(selected))
                self._refreshCryptoAlgoList()

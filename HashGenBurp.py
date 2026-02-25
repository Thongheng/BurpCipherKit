# -*- coding: utf-8 -*-
# HashGen - Burp Suite Extension
# Converts the HashGen crypto tool into a Burp Suite extension.
# Requires Jython configured in Burp Suite (Extender > Options > Python Environment).

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation,
    IMessageEditorTabFactory, IMessageEditorTab
)

from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JButton, JComboBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, BorderFactory,
    SwingUtilities, BoxLayout, Box
)
from javax.swing.border import EmptyBorder, TitledBorder
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout, Component, GridLayout
)
from java.awt.event import FocusAdapter
from javax.swing.event import DocumentListener

import json
import os
import sys
import hashlib
import hmac
import base64
import time
import traceback


# =============================================================================
# Core Logic: Snippet Manager (reused from HashGen.py)
# =============================================================================
class SnippetManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.snippets = {}
        self.load_snippets()

    def load_snippets(self):
        if not os.path.exists(self.filepath):
            self.create_default_snippets()
        try:
            with open(self.filepath, 'r') as f:
                self.snippets = json.load(f)
        except Exception as e:
            print("[HashGen] Error loading snippets: %s" % str(e))
            self.snippets = {}

    def save_snippets(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.snippets, f, indent=2)
            return True
        except Exception as e:
            print("[HashGen] Error saving snippets: %s" % str(e))
            return False

    def get_snippet(self, name):
        return self.snippets.get(name)

    def get_all_names(self):
        return list(self.snippets.keys())

    def update_snippet(self, name, code, description=""):
        self.snippets[name] = {
            "code": code,
            "description": description
        }
        self.save_snippets()

    def delete_snippet(self, name):
        if name in self.snippets:
            del self.snippets[name]
            self.save_snippets()

    def create_default_snippets(self):
        default_code = (
            "def generate(payload, passcode, api_key=\"\", key_order=None):\n"
            "    import hmac\n"
            "    import hashlib\n"
            "\n"
            "    # 1. Parse Passcode\n"
            "    if len(passcode) < 16:\n"
            "        raise ValueError(\"PassCode must be at least 16 characters long.\")\n"
            "    iv = passcode[-16:]\n"
            "    key = passcode[:-16]\n"
            "\n"
            "    # 2. Concat API Key\n"
            "    concat_str = api_key if api_key else \"\"\n"
            "\n"
            "    # 3. Determine Keys to Sign\n"
            "    keys_to_sign = []\n"
            "    if key_order:\n"
            "        keys_to_sign = key_order\n"
            "    else:\n"
            "        keys_to_sign = [k for k in payload.keys() if k != 'hash' and k != '__keys_order__']\n"
            "\n"
            "    # 4. Concat Payload Values\n"
            "    for k in keys_to_sign:\n"
            "        val = payload.get(k)\n"
            "        if val is None: val = \"\"\n"
            "        concat_str += str(val)\n"
            "\n"
            "    # 5. Create Message\n"
            "    message = iv + concat_str\n"
            "\n"
            "    # 6. Sign\n"
            "    signature = hmac.new(\n"
            "        key.encode('utf-8'),\n"
            "        message.encode('utf-8'),\n"
            "        hashlib.sha256\n"
            "    ).hexdigest()\n"
            "\n"
            "    return signature"
        )
        self.snippets["ABA HMAC SHA256"] = {
            "code": default_code,
            "description": "Original ABA HMAC-SHA256 Implementation"
        }
        self.save_snippets()


# =============================================================================
# Core Logic: Crypto Engine (reused from HashGen.py)
# =============================================================================
class CryptoEngine:
    @staticmethod
    def execute_snippet(snippet_code, payload, passcode, api_key="", key_order=None):
        local_scope = {}
        global_scope = {
            "hashlib": hashlib,
            "hmac": hmac,
            "base64": base64,
            "json": json,
            "time": time
        }

        try:
            exec(snippet_code, global_scope, local_scope)

            if "generate" not in local_scope:
                raise ValueError("Snippet must define a 'generate' function.")

            generate_func = local_scope["generate"]

            try:
                return generate_func(payload, passcode, api_key, key_order)
            except TypeError as te:
                if "argument" in str(te):
                    return generate_func(payload, passcode, api_key)
                raise te

        except Exception as e:
            return "Error: %s\n%s" % (str(e), traceback.format_exc())


# =============================================================================
# UI Helper: Focus listener for auto-formatting JSON
# =============================================================================
class PayloadFocusListener(FocusAdapter):
    def __init__(self, callback):
        self._callback = callback

    def focusLost(self, event):
        self._callback()


# =============================================================================
# UI Helper: Document listener for auto-extracting keys
# =============================================================================
class PayloadDocumentListener(DocumentListener):
    def __init__(self, callback):
        self._callback = callback

    def insertUpdate(self, event):
        self._callback()

    def removeUpdate(self, event):
        self._callback()

    def changedUpdate(self, event):
        self._callback()


# =============================================================================
# IMessageEditorTab: Inline HashGen tab in request viewer
# =============================================================================
class HashGenEditorTab(IMessageEditorTab):
    """
    Appears as a tab alongside Pretty/Raw/Hex in the request viewer.
    Optimized for inline editing: shows the request body with config controls
    to generate and inject the hash directly into the JSON body.
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        self._currentMessage = None
        self._headerBytes = None

        # Build the compact inline UI
        self._panel = JPanel(BorderLayout(3, 3))
        self._panel.setBorder(EmptyBorder(4, 4, 4, 4))

        # --- Top config bar: responsive 2-column vertical form ---
        configPanel = JPanel(GridBagLayout())
        configPanel.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(
                    BorderFactory.createLineBorder(Color(80, 80, 80)),
                    " HashGen Config ",
                    TitledBorder.LEFT, TitledBorder.TOP,
                    Font("SansSerif", Font.BOLD, 11)
                ),
                EmptyBorder(3, 5, 3, 5)
            )
        )

        gbc = GridBagConstraints()
        gbc.insets = Insets(1, 3, 1, 3)
        gbc.anchor = GridBagConstraints.WEST
        smallFont = Font("SansSerif", Font.PLAIN, 11)
        labelFont = Font("SansSerif", Font.BOLD, 11)

        names = extender.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]

        # Row 0: Algorithm
        gbc.gridy = 0
        gbc.gridx = 0
        gbc.weightx = 0
        gbc.fill = GridBagConstraints.NONE
        lbl = JLabel("Algorithm:")
        lbl.setFont(labelFont)
        configPanel.add(lbl, gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        self._algoCombo = JComboBox(names)
        self._algoCombo.setFont(smallFont)
        configPanel.add(self._algoCombo, gbc)

        # Row 1: PassCode
        gbc.gridy = 1
        gbc.gridx = 0
        gbc.weightx = 0
        gbc.fill = GridBagConstraints.NONE
        lbl = JLabel("PassCode:")
        lbl.setFont(labelFont)
        configPanel.add(lbl, gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        self._passcodeField = JTextField()
        self._passcodeField.setFont(smallFont)
        configPanel.add(self._passcodeField, gbc)

        # Row 2: API Key
        gbc.gridy = 2
        gbc.gridx = 0
        gbc.weightx = 0
        gbc.fill = GridBagConstraints.NONE
        lbl = JLabel("API Key:")
        lbl.setFont(labelFont)
        configPanel.add(lbl, gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        self._apiKeyField = JTextField()
        self._apiKeyField.setFont(smallFont)
        configPanel.add(self._apiKeyField, gbc)

        # Row 3: Keys Order
        gbc.gridy = 3
        gbc.gridx = 0
        gbc.weightx = 0
        gbc.fill = GridBagConstraints.NONE
        lbl = JLabel("Keys Order:")
        lbl.setFont(labelFont)
        configPanel.add(lbl, gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        self._keysField = JTextField()
        self._keysField.setFont(smallFont)
        configPanel.add(self._keysField, gbc)

        # Row 4: Hash Field + Buttons
        gbc.gridy = 4
        gbc.gridx = 0
        gbc.weightx = 0
        gbc.fill = GridBagConstraints.NONE
        lbl = JLabel("Hash Field:")
        lbl.setFont(labelFont)
        configPanel.add(lbl, gbc)

        gbc.gridx = 1
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        row4 = JPanel(BorderLayout(4, 0))
        self._hashFieldName = JTextField("hash")
        self._hashFieldName.setFont(smallFont)
        self._hashFieldName.setToolTipText("JSON key name where the hash will be injected")
        self._hashFieldName.setPreferredSize(Dimension(80, 24))
        row4.add(self._hashFieldName, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 3, 0))
        self._genBtn = JButton("Generate", actionPerformed=self._onGenerate)
        self._genBtn.setFont(Font("SansSerif", Font.BOLD, 11))
        self._injectBtn = JButton("Gen & Inject", actionPerformed=self._onGenerateAndInject)
        self._injectBtn.setFont(Font("SansSerif", Font.BOLD, 11))
        self._injectBtn.setToolTipText("Generate hash and inject into the JSON body")
        btnPanel.add(self._genBtn)
        btnPanel.add(self._injectBtn)
        row4.add(btnPanel, BorderLayout.EAST)
        configPanel.add(row4, gbc)

        self._panel.add(configPanel, BorderLayout.NORTH)

        # --- Center: Body editor + hash output (vertical split) ---
        centerPanel = JPanel(BorderLayout(0, 5))

        # Body text area (editable request body)
        self._bodyArea = JTextArea(15, 60)
        self._bodyArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._bodyArea.setLineWrap(True)
        self._bodyArea.setWrapStyleWord(True)
        self._bodyArea.setEditable(editable)

        # Auto-extract keys when body changes
        self._bodyArea.getDocument().addDocumentListener(
            PayloadDocumentListener(self._tryExtractKeys)
        )
        # Auto-format JSON on focus lost
        self._bodyArea.addFocusListener(
            PayloadFocusListener(self._tryFormatJson)
        )

        bodyScroll = JScrollPane(self._bodyArea)
        bodyScroll.setBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(80, 80, 80)),
                " Request Body (editable) ",
                TitledBorder.LEFT, TitledBorder.TOP,
                Font("SansSerif", Font.PLAIN, 11)
            )
        )

        # Hash output (read-only, compact)
        self._hashOutput = JTextArea(3, 60)
        self._hashOutput.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._hashOutput.setEditable(False)
        self._hashOutput.setLineWrap(True)
        self._hashOutput.setWrapStyleWord(True)

        hashScroll = JScrollPane(self._hashOutput)
        hashScroll.setBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(80, 80, 80)),
                " Generated Hash ",
                TitledBorder.LEFT, TitledBorder.TOP,
                Font("SansSerif", Font.PLAIN, 11)
            )
        )
        hashScroll.setPreferredSize(Dimension(0, 80))

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, bodyScroll, hashScroll)
        splitPane.setResizeWeight(0.8)
        centerPanel.add(splitPane, BorderLayout.CENTER)

        self._panel.add(centerPanel, BorderLayout.CENTER)

        # Sync config fields from the main tab if available
        self._syncFromMainTab()

    def _syncFromMainTab(self):
        """Copy config values from the main HashGen tab to this inline tab."""
        try:
            ext = self._extender
            passcode = ext._passcodeField.getText()
            if passcode:
                self._passcodeField.setText(passcode)
            api_key = ext._apiKeyField.getText()
            if api_key:
                self._apiKeyField.setText(api_key)
            # Sync algorithm selection
            mainAlgo = ext._algoCombo.getSelectedItem()
            if mainAlgo:
                self._algoCombo.setSelectedItem(mainAlgo)
        except:
            pass

    # --- IMessageEditorTab interface ---

    def getTabCaption(self):
        return "HashGen"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        # Only show for requests that have a body
        if not isRequest or content is None:
            return False
        try:
            analyzed = self._helpers.analyzeRequest(content)
            bodyOffset = analyzed.getBodyOffset()
            body = self._helpers.bytesToString(content[bodyOffset:])
            # Show tab if body is non-empty (especially for JSON bodies)
            return len(body.strip()) > 0
        except:
            return False

    def setMessage(self, content, isRequest):
        if content is None:
            self._bodyArea.setText("")
            self._currentMessage = None
            self._headerBytes = None
            return

        self._currentMessage = content
        analyzed = self._helpers.analyzeRequest(content)
        bodyOffset = analyzed.getBodyOffset()

        # Store headers portion for rebuilding  
        self._headerBytes = content[:bodyOffset]

        body = self._helpers.bytesToString(content[bodyOffset:])

        # Try to pretty-print JSON
        try:
            parsed = json.loads(body)
            body = json.dumps(parsed, indent=2)
        except:
            pass

        self._bodyArea.setText(body)
        self._bodyArea.setCaretPosition(0)

        # Auto-extract keys
        self._tryExtractKeys()

        # Sync config from main tab
        self._syncFromMainTab()

    def getMessage(self):
        """Return the modified HTTP message (headers + edited body)."""
        if self._currentMessage is None:
            return self._currentMessage

        body_str = self._bodyArea.getText().strip()

        # Compact the JSON if valid (remove pretty-print for wire format)
        try:
            parsed = json.loads(body_str)
            body_str = json.dumps(parsed)
        except:
            pass

        body_bytes = self._helpers.stringToBytes(body_str)

        # Rebuild: original headers + new body
        analyzed = self._helpers.analyzeRequest(self._currentMessage)
        headers = analyzed.getHeaders()
        return self._helpers.buildHttpMessage(headers, body_bytes)

    def isModified(self):
        if self._currentMessage is None:
            return False
        # Compare current body text to original
        analyzed = self._helpers.analyzeRequest(self._currentMessage)
        bodyOffset = analyzed.getBodyOffset()
        originalBody = self._helpers.bytesToString(self._currentMessage[bodyOffset:])

        currentBody = self._bodyArea.getText().strip()
        # Normalize both for comparison
        try:
            orig = json.dumps(json.loads(originalBody))
            curr = json.dumps(json.loads(currentBody))
            return orig != curr
        except:
            return originalBody.strip() != currentBody

    def getSelectedData(self):
        selected = self._bodyArea.getSelectedText()
        if selected:
            return self._helpers.stringToBytes(selected)
        return None

    # --- Actions ---

    def _onGenerate(self, event=None):
        """Generate hash and show in the output area."""
        result = self._computeHash()
        self._hashOutput.setText(str(result))

    def _onGenerateAndInject(self, event=None):
        """Generate hash and inject it into the JSON body."""
        result = self._computeHash()
        if result and not str(result).startswith("Error"):
            self._hashOutput.setText(str(result))
            # Inject into body
            body_str = self._bodyArea.getText().strip()
            try:
                data = json.loads(body_str)
                field_name = self._hashFieldName.getText().strip()
                if not field_name:
                    field_name = "hash"
                data[field_name] = str(result)
                self._bodyArea.setText(json.dumps(data, indent=2))
                self._bodyArea.setCaretPosition(0)
            except Exception as e:
                self._hashOutput.setText("Error injecting hash: %s" % str(e))
        else:
            self._hashOutput.setText(str(result))

    def _computeHash(self):
        """Run the selected snippet against the current body."""
        name = self._algoCombo.getSelectedItem()
        if not name:
            return "Error: No algorithm selected."

        snippet = self._extender.snippet_manager.get_snippet(str(name))
        if not snippet:
            return "Error: Snippet '%s' not found." % name

        try:
            body_str = self._bodyArea.getText().strip()
            payload = json.loads(body_str)
            passcode = self._passcodeField.getText()
            api_key = self._apiKeyField.getText()

            keys_str = self._keysField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            return CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, api_key, key_order
            )
        except ValueError:
            return "Error: Invalid JSON body"
        except Exception as e:
            return "Error: %s" % str(e)

    def _tryExtractKeys(self):
        """Auto-extract keys from JSON body."""
        try:
            body_str = self._bodyArea.getText().strip()
            if not body_str:
                return
            data = json.loads(body_str)
            if isinstance(data, dict):
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysField.getText().strip()
                if current != new_keys_str:
                    self._keysField.setText(new_keys_str)
        except:
            pass

    def _tryFormatJson(self):
        """Auto-format JSON on focus lost."""
        try:
            body_str = self._bodyArea.getText().strip()
            if not body_str:
                return
            data = json.loads(body_str)
            formatted = json.dumps(data, indent=2)
            if formatted != body_str:
                self._bodyArea.setText(formatted)
        except:
            pass


# =============================================================================
# Burp Suite Extension Entry Point
# =============================================================================
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HashGen")

        # Redirect stdout/stderr to Burp's output
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Snippet manager
        ext_file = callbacks.getExtensionFilename()
        script_dir = os.path.dirname(os.path.abspath(ext_file))
        snippets_path = os.path.join(script_dir, "snippets.json")
        self.snippet_manager = SnippetManager(snippets_path)

        # Build main tab UI synchronously
        SwingUtilities.invokeAndWait(self._buildUI)

        # Register all factories
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)

        # Register the main HashGen tab
        callbacks.addSuiteTab(self)

        print("[+] HashGen extension loaded successfully")
        print("[*] Snippets file: %s" % snippets_path)
        print("[*] HashGen tab added to request editor views")

    # -------------------------------------------------------------------------
    # ITab implementation
    # -------------------------------------------------------------------------
    def getTabCaption(self):
        return "HashGen"

    def getUiComponent(self):
        return self._mainPanel

    # -------------------------------------------------------------------------
    # IMessageEditorTabFactory implementation
    # -------------------------------------------------------------------------
    def createNewInstance(self, controller, editable):
        return HashGenEditorTab(self, controller, editable)

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
            item = JMenuItem("Send to HashGen")
            item.addActionListener(lambda event: self._onContextMenuSend(invocation))
            menu_items.append(item)

        return menu_items if menu_items else None

    def _onContextMenuSend(self, invocation):
        """Extract request body and populate the Generator payload field."""
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

                    # Switch to the HashGen tab
                    parent = self._mainPanel.getParent()
                    if parent:
                        idx = parent.indexOfComponent(self._mainPanel)
                        if idx >= 0:
                            parent.setSelectedIndex(idx)

                    self._tabbedPane.setSelectedIndex(0)
                    print("[*] Request body sent to HashGen Generator")

    # -------------------------------------------------------------------------
    # Build the Main Tab UI
    # -------------------------------------------------------------------------
    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Header
        headerPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        titleLabel = JLabel("HashGen")
        titleLabel.setFont(Font("SansSerif", Font.BOLD, 20))
        subtitleLabel = JLabel("  -  Universal Crypto Hash Generator")
        subtitleLabel.setFont(Font("SansSerif", Font.PLAIN, 14))
        subtitleLabel.setForeground(Color(130, 130, 130))
        headerPanel.add(titleLabel)
        headerPanel.add(subtitleLabel)
        self._mainPanel.add(headerPanel, BorderLayout.NORTH)

        # Tabbed pane for Generator / Editor
        self._tabbedPane = JTabbedPane()
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)

        generatorPanel = self._buildGeneratorTab()
        editorPanel = self._buildEditorTab()

        self._tabbedPane.addTab("Generator", generatorPanel)
        self._tabbedPane.addTab("Snippet Editor", editorPanel)

    # -------------------------------------------------------------------------
    # Generator Tab
    # -------------------------------------------------------------------------
    def _buildGeneratorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # --- Left side: inputs ---
        leftPanel = JPanel()
        leftPanel.setLayout(BoxLayout(leftPanel, BoxLayout.Y_AXIS))
        leftPanel.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(
                    BorderFactory.createLineBorder(Color(80, 80, 80)),
                    " Configuration ",
                    TitledBorder.LEFT, TitledBorder.TOP,
                    Font("SansSerif", Font.BOLD, 12)
                ),
                EmptyBorder(10, 10, 10, 10)
            )
        )
        leftPanel.setPreferredSize(Dimension(320, 0))

        # Algorithm selector
        leftPanel.add(self._createLabel("Algorithm:"))
        leftPanel.add(Box.createVerticalStrut(4))
        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        self._algoCombo = JComboBox(names)
        self._algoCombo.setMaximumSize(Dimension(9999, 30))
        leftPanel.add(self._algoCombo)
        leftPanel.add(Box.createVerticalStrut(12))

        # Passcode
        leftPanel.add(self._createLabel("PassCode (Key+IV):"))
        leftPanel.add(Box.createVerticalStrut(4))
        self._passcodeField = JTextField()
        self._passcodeField.setMaximumSize(Dimension(9999, 30))
        leftPanel.add(self._passcodeField)
        leftPanel.add(Box.createVerticalStrut(12))

        # API Key
        leftPanel.add(self._createLabel("API Key (Optional):"))
        leftPanel.add(Box.createVerticalStrut(4))
        self._apiKeyField = JTextField()
        self._apiKeyField.setMaximumSize(Dimension(9999, 30))
        leftPanel.add(self._apiKeyField)
        leftPanel.add(Box.createVerticalStrut(12))

        # Keys Order
        leftPanel.add(self._createLabel("Keys Order (comma separated):"))
        leftPanel.add(Box.createVerticalStrut(4))
        self._keysOrderField = JTextField()
        self._keysOrderField.setMaximumSize(Dimension(9999, 30))
        leftPanel.add(self._keysOrderField)
        leftPanel.add(Box.createVerticalStrut(20))

        # Generate button
        self._generateBtn = JButton("Generate Hash", actionPerformed=self._onGenerate)
        self._generateBtn.setFont(Font("SansSerif", Font.BOLD, 14))
        self._generateBtn.setMaximumSize(Dimension(9999, 45))
        self._generateBtn.setAlignmentX(Component.CENTER_ALIGNMENT)
        leftPanel.add(self._generateBtn)

        leftPanel.add(Box.createVerticalGlue())

        # --- Right side: text areas ---
        rightPanel = JPanel(GridBagLayout())
        rightPanel.setBorder(EmptyBorder(0, 0, 0, 0))
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(2, 0, 2, 0)
        gbc.gridx = 0
        gbc.weightx = 1.0

        # Payload label
        gbc.gridy = 0
        gbc.weighty = 0
        payloadLabel = self._createLabel("JSON Payload:")
        rightPanel.add(payloadLabel, gbc)

        # Payload text area
        gbc.gridy = 1
        gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        self._payloadArea = JTextArea(12, 40)
        self._payloadArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._payloadArea.setLineWrap(True)
        self._payloadArea.setWrapStyleWord(True)
        self._payloadArea.setText('{\n  "username": "user",\n  "request_time": "20260101010101"\n}')

        self._payloadArea.getDocument().addDocumentListener(
            PayloadDocumentListener(self._tryExtractKeys)
        )
        self._payloadArea.addFocusListener(
            PayloadFocusListener(self._tryFormatJson)
        )

        payloadScroll = JScrollPane(self._payloadArea)
        payloadScroll.setBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(80, 80, 80)),
                " Payload ",
                TitledBorder.LEFT, TitledBorder.TOP,
                Font("SansSerif", Font.PLAIN, 11)
            )
        )
        rightPanel.add(payloadScroll, gbc)

        # Output label
        gbc.gridy = 2
        gbc.weighty = 0
        gbc.fill = GridBagConstraints.HORIZONTAL
        outputLabel = self._createLabel("Output:")
        rightPanel.add(outputLabel, gbc)

        # Output text area
        gbc.gridy = 3
        gbc.weighty = 0.6
        gbc.fill = GridBagConstraints.BOTH
        self._outputArea = JTextArea(6, 40)
        self._outputArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._outputArea.setLineWrap(True)
        self._outputArea.setWrapStyleWord(True)
        self._outputArea.setEditable(False)

        outputScroll = JScrollPane(self._outputArea)
        outputScroll.setBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(80, 80, 80)),
                " Result ",
                TitledBorder.LEFT, TitledBorder.TOP,
                Font("SansSerif", Font.PLAIN, 11)
            )
        )
        rightPanel.add(outputScroll, gbc)

        # Combine left + right
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(320)
        splitPane.setResizeWeight(0.0)
        panel.add(splitPane, BorderLayout.CENTER)

        return panel

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
        self._snippetNameField.setFont(Font("SansSerif", Font.PLAIN, 14))
        self._snippetNameField.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color(80, 80, 80)),
                EmptyBorder(6, 8, 6, 8)
            )
        )
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
        infoLabel = JLabel("Python code must define: generate(payload, passcode, api_key=\"\", key_order=None)")
        infoLabel.setFont(Font("SansSerif", Font.ITALIC, 11))
        infoLabel.setForeground(Color(130, 130, 130))

        # Code editor area
        self._codeArea = JTextArea(20, 60)
        self._codeArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._codeArea.setTabSize(4)
        self._codeArea.setLineWrap(False)

        default_template = (
            'def generate(payload, passcode, api_key="", key_order=None):\n'
            '    import hashlib\n'
            '    # Implement your logic here\n'
            '    # key_order is a list of keys if provided by user\n'
            '    return "hash_result"'
        )
        self._codeArea.setText(default_template)

        codeScroll = JScrollPane(self._codeArea)
        codeScroll.setBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(80, 80, 80)),
                " Snippet Code ",
                TitledBorder.LEFT, TitledBorder.TOP,
                Font("SansSerif", Font.BOLD, 12)
            )
        )

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
        label.setFont(Font("SansSerif", Font.BOLD, 12))
        label.setAlignmentX(Component.LEFT_ALIGNMENT)
        return label

    # -------------------------------------------------------------------------
    # Actions: Generator
    # -------------------------------------------------------------------------
    def _onGenerate(self, event=None):
        name = self._algoCombo.getSelectedItem()
        if not name:
            self._outputArea.setText("Error: No algorithm selected.")
            return

        snippet = self.snippet_manager.get_snippet(str(name))
        if not snippet:
            self._outputArea.setText("Error: Snippet '%s' not found." % name)
            return

        try:
            payload_str = self._payloadArea.getText().strip()
            payload = json.loads(payload_str)
            passcode = self._passcodeField.getText()
            api_key = self._apiKeyField.getText()

            keys_str = self._keysOrderField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            result = CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, api_key, key_order
            )

            self._outputArea.setText(str(result))

        except ValueError as ve:
            self._outputArea.setText("Error: Invalid JSON Payload\n%s" % str(ve))
        except Exception as e:
            self._outputArea.setText("Error: %s" % str(e))

    def _tryExtractKeys(self):
        """Auto-extract keys from JSON payload."""
        try:
            payload_str = self._payloadArea.getText().strip()
            if not payload_str:
                return
            data = json.loads(payload_str)
            if isinstance(data, dict):
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysOrderField.getText().strip()
                if current != new_keys_str:
                    self._keysOrderField.setText(new_keys_str)
        except:
            pass

    def _tryFormatJson(self):
        """Auto-format JSON on focus lost."""
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
        code = self._codeArea.getText().strip()

        if not name:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "Please enter a snippet name.",
                "HashGen - Save Error",
                JOptionPane.WARNING_MESSAGE
            )
            return

        self.snippet_manager.update_snippet(name, code)
        self._refreshAlgoList()
        JOptionPane.showMessageDialog(
            self._mainPanel,
            "Snippet '%s' saved successfully." % name,
            "HashGen",
            JOptionPane.INFORMATION_MESSAGE
        )
        print("[*] Snippet saved: %s" % name)

    def _onLoadSnippet(self, event=None):
        names = self.snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "No snippets available.",
                "HashGen - Load",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        selected = JOptionPane.showInputDialog(
            self._mainPanel,
            "Select a snippet to load:",
            "HashGen - Load Snippet",
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
                "HashGen",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        selected = JOptionPane.showInputDialog(
            self._mainPanel,
            "Select a snippet to delete:",
            "HashGen - Delete Snippet",
            JOptionPane.WARNING_MESSAGE,
            None,
            names,
            names[0]
        )

        if selected:
            confirm = JOptionPane.showConfirmDialog(
                self._mainPanel,
                "Are you sure you want to delete '%s'?" % selected,
                "HashGen - Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                self.snippet_manager.delete_snippet(str(selected))
                self._refreshAlgoList()
                print("[*] Snippet deleted: %s" % selected)

    def _refreshAlgoList(self):
        """Refresh the algorithm dropdown in the Generator tab."""
        self._algoCombo.removeAllItems()
        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        for name in names:
            self._algoCombo.addItem(name)

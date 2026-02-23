# -*- coding: utf-8 -*-
# HashGen - Burp Suite Extension
# Converts the HashGen crypto tool into a Burp Suite extension.
# Requires Jython configured in Burp Suite (Extender → Options → Python Environment).

from burp import IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation

from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JButton, JComboBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, BorderFactory,
    SwingUtilities, BoxLayout, Box
)
from javax.swing.border import EmptyBorder, TitledBorder
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout, Component
)
from java.awt.event import FocusListener, FocusAdapter, ActionListener
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
# Burp Suite Extension Entry Point
# =============================================================================
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HashGen")

        # Redirect stdout/stderr to Burp's output
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Snippet manager — snippets.json lives next to extension file
        # Note: __file__ is not available in Jython when loaded by Burp,
        # so we use the Burp API to get the extension's file path.
        ext_file = callbacks.getExtensionFilename()
        script_dir = os.path.dirname(os.path.abspath(ext_file))
        snippets_path = os.path.join(script_dir, "snippets.json")
        self.snippet_manager = SnippetManager(snippets_path)

        # Build UI synchronously on the Swing EDT — MUST complete before
        # addSuiteTab, because Burp calls getUiComponent() immediately.
        SwingUtilities.invokeAndWait(self._buildUI)

        # Register context menu
        callbacks.registerContextMenuFactory(self)

        # Register the custom tab (safe now — _mainPanel exists)
        callbacks.addSuiteTab(self)

        print("[+] HashGen extension loaded successfully")
        print("[*] Snippets file: %s" % snippets_path)

    # -------------------------------------------------------------------------
    # ITab implementation
    # -------------------------------------------------------------------------
    def getTabCaption(self):
        return "HashGen"

    def getUiComponent(self):
        return self._mainPanel

    # -------------------------------------------------------------------------
    # IContextMenuFactory implementation
    # -------------------------------------------------------------------------
    def createMenuItems(self, invocation):
        from javax.swing import JMenuItem
        menu_items = []

        ctx = invocation.getInvocationContext()
        # Show menu item for requests in various Burp tools
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
                    # Try to pretty-print if JSON
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

                    # Switch to Generator sub-tab
                    self._tabbedPane.setSelectedIndex(0)

                    print("[*] Request body sent to HashGen Generator")

    # -------------------------------------------------------------------------
    # Build the UI
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

        # Build tabs
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

        # Document listener for auto-extract keys
        self._payloadArea.getDocument().addDocumentListener(
            PayloadDocumentListener(self._tryExtractKeys)
        )
        # Focus listener for auto-format JSON
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

        # Combine left + right with a split pane
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
    # UI Helper: create a styled label
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

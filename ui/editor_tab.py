# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os, sys, hashlib, hmac, base64, time, traceback, itertools
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JButton, JComboBox, JCheckBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, BorderFactory,
    SwingUtilities, BoxLayout, Box
)
from javax.swing.border import EmptyBorder, TitledBorder, AbstractBorder
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout, Component, GridLayout, RenderingHints
)
from java.awt.event import FocusAdapter, ActionListener
from javax.swing.event import DocumentListener
from javax.swing import Timer as _SwingTimer

from burp import IMessageEditorTab
from core.utils import _safe_encode, _DEBOUNCE_MS, _MONO_FONT_SIZE, _MAX_KF_FIELDS
from core.body_parser import parse_body, serialize_body
from core.snippet_manager import SnippetManager
from core.crypto_engine import CryptoEngine, AesCbcEngine
from core.crypto_snippet_manager import CryptoSnippetManager
from core.crypto_snippet_engine import CryptoSnippetEngine
from core.app_setting_manager import AppSettingManager
from ui.components.rounded_border import RoundedBorder, _roundedCompound
from ui.components.custom_data_panel import CustomDataPanel, CompactCustomDataPanel
from ui.components.listeners import PayloadFocusListener, PayloadDocumentListener

class HashGenEditorTab(IMessageEditorTab):
    """
    Appears as a tab alongside Pretty/Raw/Hex in the request viewer.
    Two sub-tabs (Hash / Crypto) let users switch config view;
    both are always active and work simultaneously.
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers  = extender._helpers
        self._editable = editable
        self._isRequestContext = False
        self._currentMessage = None
        self._headerBytes    = None
        self._contentType    = ""
        self._keysUserEdited = False
        self._lastHashText   = ""  # saved hash result; restored when returning to Hash tab

        # Fonts
        monoFont  = Font("Monospaced", Font.PLAIN, 12)

        # ---- Root panel ----
        self._panel = JPanel(BorderLayout(3, 3))
        self._panel.setBorder(EmptyBorder(4, 4, 4, 4))

        # ================================================================
        # TOP: compact JTabbedPane with Hash sub-tab and Crypto sub-tab
        # ================================================================
        configTabs = JTabbedPane(JTabbedPane.TOP)

        # ----------------------------------------------------------------
        # Hash sub-tab panel
        # ----------------------------------------------------------------
        hashConfigPanel = JPanel(GridBagLayout())
        hashConfigPanel.setBorder(EmptyBorder(4, 5, 4, 5))

        hgbc = GridBagConstraints()
        hgbc.insets  = Insets(1, 3, 1, 3)
        hgbc.anchor  = GridBagConstraints.WEST

        names = extender.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]

        # Row 0: Algorithm
        hgbc.gridy = 0; hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE
        hashConfigPanel.add(JLabel("Algorithm:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        self._algoCombo = JComboBox(names)
        self._algoCombo.addActionListener(lambda e: self._updateInlinePasscodeState())
        hashConfigPanel.add(self._algoCombo, hgbc)

        # Row 1: Secret
        hgbc.gridy = 1; hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE
        self._passcodeLbl = JLabel("Secret:")
        hashConfigPanel.add(self._passcodeLbl, hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        self._passcodeField = JTextField()
        hashConfigPanel.add(self._passcodeField, hgbc)

        # Row 2: Custom Data
        hgbc.gridy = 2; hgbc.gridx = 0; hgbc.weightx = 0
        hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.NORTHWEST
        hashConfigPanel.add(JLabel("Custom Data:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        hgbc.anchor = GridBagConstraints.WEST
        self._customDataPanel = CompactCustomDataPanel()
        hashConfigPanel.add(self._customDataPanel, hgbc)

        # Row 3: Keys Order
        hgbc.gridy = 3; hgbc.gridx = 0; hgbc.weightx = 0
        hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.WEST
        hashConfigPanel.add(JLabel("Sign Order:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        self._keysField = JTextField()
        self._keysField.getDocument().addDocumentListener(
            PayloadDocumentListener(self._onKeysManualEdit)
        )
        hashConfigPanel.add(self._keysField, hgbc)

        # Row 4: Hash Field + Buttons
        hgbc.gridy = 4; hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE
        hashConfigPanel.add(JLabel("Output Field:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        hashRow = JPanel(BorderLayout(4, 0))
        self._hashFieldName = JTextField("hash")
        self._hashFieldName.setToolTipText("JSON key name where the output will be injected")
        self._hashFieldName.setPreferredSize(Dimension(70, 22))
        hashRow.add(self._hashFieldName, BorderLayout.CENTER)
        hashBtnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 3, 0))
        self._genBtn    = JButton("Generate",     actionPerformed=self._onGenerate)
        self._injectBtn = JButton("Gen & Inject", actionPerformed=self._onGenerateAndInject)
        self._injectBtn.setToolTipText("Generate hash and inject into the request body")
        hashBtnPanel.add(self._genBtn)
        hashBtnPanel.add(self._injectBtn)
        hashRow.add(hashBtnPanel, BorderLayout.EAST)
        hashConfigPanel.add(hashRow, hgbc)


        # ----------------------------------------------------------------
        # Crypto sub-tab panel
        # ----------------------------------------------------------------
        cryptoConfigPanel = JPanel(GridBagLayout())
        cryptoConfigPanel.setBorder(EmptyBorder(4, 5, 4, 5))

        cgbc = GridBagConstraints()
        cgbc.insets  = Insets(1, 3, 1, 3)
        cgbc.anchor  = GridBagConstraints.WEST

        # Mode kept as hidden widget - logic uses Decrypt on open, Encrypt on edit
        self._inlineCryptoMode = JComboBox(["Decrypt", "Encrypt"])

        # Row 0: Algorithm
        cgbc.gridy = 0; cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        cryptoConfigPanel.add(JLabel("Algorithm:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 1.0; cgbc.fill = GridBagConstraints.HORIZONTAL
        crypto_names = extender.crypto_snippet_manager.get_all_names()
        if not crypto_names:
            crypto_names = ["(no algorithms)"]
        self._inlineCryptoAlgo = JComboBox(crypto_names)
        cryptoConfigPanel.add(self._inlineCryptoAlgo, cgbc)

        # Row 1: Key
        cgbc.gridy = 1; cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        cryptoConfigPanel.add(JLabel("Key:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 1.0; cgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineCryptoKey = JTextField()
        self._inlineCryptoKey.setToolTipText("")
        cryptoConfigPanel.add(self._inlineCryptoKey, cgbc)

        # Row 2: IV
        cgbc.gridy = 2; cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        self._inlineCryptoIvLbl = JLabel("IV:")
        cryptoConfigPanel.add(self._inlineCryptoIvLbl, cgbc)
        cgbc.gridx = 1; cgbc.weightx = 1.0; cgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineCryptoIv = JTextField()
        self._inlineCryptoIv.setToolTipText("")
        cryptoConfigPanel.add(self._inlineCryptoIv, cgbc)

        # Row 3: Target Field + Buttons
        cgbc.gridy = 3; cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        cryptoConfigPanel.add(JLabel("Field:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 1.0; cgbc.fill = GridBagConstraints.HORIZONTAL
        cryptoRow = JPanel(BorderLayout(4, 0))
        self._inlineCryptoField = JTextField("data")
        self._inlineCryptoField.setToolTipText(
            "JSON field to read (Decrypt) or write result to (Encrypt). "
            "For Encrypt, the plaintext is taken from this body field and result injected back."
        )
        self._inlineCryptoField.setPreferredSize(Dimension(70, 22))
        cryptoRow.add(self._inlineCryptoField, BorderLayout.CENTER)
        cryptoBtnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 3, 0))
        self._cryptoRunBtn = JButton("Run Crypto", actionPerformed=self._onCryptoRun)
        self._cryptoRunBtn.setToolTipText("Manually run encrypt/decrypt on the body field")
        cryptoBtnPanel.add(self._cryptoRunBtn)
        cryptoRow.add(cryptoBtnPanel, BorderLayout.EAST)
        cryptoConfigPanel.add(cryptoRow, cgbc)

        # ----------------------------------------------------------------
        # Key Finder sub-tab panel (compact controls only - no Parsed/Results)
        # Parsed Fields + Results live in the CENTER card to avoid inflating
        # the configTabs height for Hash/Crypto tabs.
        # ----------------------------------------------------------------
        kfPanel = JPanel(GridBagLayout())
        kfPanel.setBorder(EmptyBorder(4, 5, 4, 5))

        kgbc = GridBagConstraints()
        kgbc.insets = Insets(2, 3, 2, 3)
        kgbc.anchor = GridBagConstraints.WEST

        # Row 0: Body Format + Parse button
        kgbc.gridy = 0; kgbc.gridx = 0; kgbc.weightx = 0; kgbc.fill = GridBagConstraints.NONE
        kfPanel.add(JLabel("Body Format:"), kgbc)
        kgbc.gridx = 1; kgbc.weightx = 1.0; kgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineKfFormatCombo = JComboBox(["JSON", "Form Data"])
        kfPanel.add(self._inlineKfFormatCombo, kgbc)
        kgbc.gridx = 2; kgbc.weightx = 0; kgbc.fill = GridBagConstraints.NONE
        inlineParseBtn = JButton("Parse Body", actionPerformed=self._onInlineKfParse)
        kfPanel.add(inlineParseBtn, kgbc)

        # Row 1: Extra Fields (N-06: CompactCustomDataPanel replaces free-text JTextArea)
        kgbc.gridy = 1; kgbc.gridx = 0; kgbc.weightx = 0; kgbc.fill = GridBagConstraints.NONE
        kgbc.anchor = GridBagConstraints.NORTHWEST
        kfPanel.add(JLabel("Extra Fields:"), kgbc)
        kgbc.gridx = 1; kgbc.gridwidth = 2; kgbc.weightx = 1.0; kgbc.fill = GridBagConstraints.HORIZONTAL
        kgbc.anchor = GridBagConstraints.WEST
        self._inlineKfAdditionalPanel = CompactCustomDataPanel()
        self._inlineKfAdditionalPanel.setToolTipText("Extra fields not in body, e.g. API: abc123")
        kfPanel.add(self._inlineKfAdditionalPanel, kgbc)
        kgbc.gridwidth = 1

        # Row 2: Known String
        kgbc.gridy = 2; kgbc.gridx = 0; kgbc.weightx = 0; kgbc.fill = GridBagConstraints.NONE
        kgbc.anchor = GridBagConstraints.NORTHWEST
        kfPanel.add(JLabel("Known String:"), kgbc)
        kgbc.gridx = 1; kgbc.gridwidth = 2; kgbc.weightx = 1.0; kgbc.fill = GridBagConstraints.HORIZONTAL
        kgbc.anchor = GridBagConstraints.WEST
        self._inlineKfKnownArea = JTextArea(2, 40)
        self._inlineKfKnownArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._inlineKfKnownArea.setLineWrap(True)
        kfPanel.add(JScrollPane(self._inlineKfKnownArea), kgbc)
        kgbc.gridwidth = 1

        # Row 3: Find button
        kgbc.gridy = 3; kgbc.gridx = 0; kgbc.gridwidth = 3; kgbc.weightx = 1.0
        kgbc.fill = GridBagConstraints.HORIZONTAL; kgbc.anchor = GridBagConstraints.WEST
        inlineFindBtn = JButton("Find Key Order", actionPerformed=self._onInlineKfFind)
        kfPanel.add(inlineFindBtn, kgbc)

        # ----------------------------------------------------------------
        # AppSetting sub-tab panel
        # ----------------------------------------------------------------
        appSettingTabPanel = JPanel(GridBagLayout())
        appSettingTabPanel.setBorder(EmptyBorder(6, 6, 6, 6))
        pgbc = GridBagConstraints()
        pgbc.insets = Insets(3, 4, 3, 4)
        pgbc.anchor = GridBagConstraints.WEST

        # Row 0: App selector + Load + Delete
        pgbc.gridy = 0; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("App:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_setting_names = ["(none)"] + extender.app_setting_manager.get_all_names()
        self._inlineSettingCombo = JComboBox(_pt_setting_names)
        self._inlineSettingCombo.setToolTipText("Select app setting to load (algorithm, secret, crypto settings)")
        self._inlineSettingCombo.addActionListener(lambda e: self._refreshInlineSettingInfo())
        _pt_appRow = JPanel(BorderLayout(4, 0))
        _pt_appRow.add(self._inlineSettingCombo, BorderLayout.CENTER)
        _pt_appBtns = JPanel(FlowLayout(FlowLayout.RIGHT, 3, 0))
        _pt_loadBtn = JButton("Load", actionPerformed=self._onInlineLoadSetting)
        _pt_loadBtn.setToolTipText("Load selected app setting into all config fields")
        _pt_delBtn  = JButton("Delete App", actionPerformed=self._onInlineDeleteSetting)
        _pt_delBtn.setToolTipText("Delete this app setting and all its endpoints")
        _pt_appBtns.add(_pt_loadBtn)
        _pt_appBtns.add(_pt_delBtn)
        _pt_appRow.add(_pt_appBtns, BorderLayout.EAST)
        appSettingTabPanel.add(_pt_appRow, pgbc)

        # Row 1: Current URL (read-only info)
        pgbc.gridy = 1; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("Current URL:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineUrlLabel = JTextField("")
        self._inlineUrlLabel.setEditable(False)
        self._inlineUrlLabel.setForeground(Color(80, 80, 80))
        appSettingTabPanel.add(self._inlineUrlLabel, pgbc)

        # Row 2: Endpoint keys order (editable, linked to main keys field)
        pgbc.gridy = 2; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("Sign Order:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_epRow = JPanel(BorderLayout(4, 0))
        self._inlineEpKeysField = JTextField("")
        self._inlineEpKeysField.setToolTipText("Keys order for this endpoint (comma-separated)")
        _pt_epRow.add(self._inlineEpKeysField, BorderLayout.CENTER)
        _pt_saveEpBtn = JButton("Save Endpoint", actionPerformed=self._onInlineSaveSetting)
        _pt_saveEpBtn.setToolTipText(
            "Save this URL + keys order under the selected app.\n"
            "Do this once per endpoint - it auto-loads next time."
        )
        _pt_epRow.add(_pt_saveEpBtn, BorderLayout.EAST)
        appSettingTabPanel.add(_pt_epRow, pgbc)

        # Row 3: Status / last auto-load info
        pgbc.gridy = 3; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("Status:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineSettingStatus = JTextField("No setting loaded")
        self._inlineSettingStatus.setEditable(False)
        self._inlineSettingStatus.setForeground(Color(80, 80, 80))
        appSettingTabPanel.add(self._inlineSettingStatus, pgbc)

        # Filler row to push content to top
        pgbc.gridy = 4; pgbc.gridx = 0; pgbc.gridwidth = 2
        pgbc.weighty = 1.0; pgbc.fill = GridBagConstraints.VERTICAL
        appSettingTabPanel.add(JPanel(), pgbc)

        configTabs.addTab("Hash",       hashConfigPanel)
        configTabs.addTab("Crypto",     cryptoConfigPanel)
        configTabs.addTab("Key Finder", kfPanel)
        configTabs.addTab("AppSetting",     appSettingTabPanel)

        # Timestamp sub-tab panel
        timestampConfigPanel = JPanel(GridBagLayout())
        timestampConfigPanel.setBorder(EmptyBorder(6, 6, 6, 6))
        tgbc = GridBagConstraints()
        tgbc.insets = Insets(3, 4, 3, 4)
        tgbc.anchor = GridBagConstraints.WEST

        # Row 0: Option checkbox
        tgbc.gridy = 0; tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE
        self._inlineTsAutoCopyChk = JCheckBox("Auto-copy to clipboard", True)
        timestampConfigPanel.add(self._inlineTsAutoCopyChk, tgbc)

        # Row 0, Col 1: Buttons
        tgbc.gridx = 1; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        tsRow = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        tBtn = JButton("Get Timestamp", actionPerformed=self._onInlineGetTimestamp)
        tCopyBtn = JButton("Copy", actionPerformed=self._onInlineCopyTimestamp)
        tsRow.add(tBtn)
        tsRow.add(tCopyBtn)
        timestampConfigPanel.add(tsRow, tgbc)

        # Filler row to match the height of other sub-tabs
        tgbc.gridy = 1; tgbc.gridx = 0; tgbc.gridwidth = 2
        tgbc.weighty = 1.0; tgbc.fill = GridBagConstraints.VERTICAL
        timestampConfigPanel.add(JPanel(), tgbc)

        configTabs.addTab("Timestamp",  timestampConfigPanel)

        self._configTabs = configTabs
        self._panel.add(configTabs, BorderLayout.NORTH)

        # ================================================================
        # CENTER: CardLayout - switches between Hash/Crypto view and KF view
        # ================================================================
        from java.awt import CardLayout as _CardLayout
        self._cardLayout  = _CardLayout()
        centerPanel = JPanel(self._cardLayout)

        # ---- Card 1: Hash/Crypto - Request Body + Output ----
        hashCryptoCard = JPanel(BorderLayout(0, 4))

        bodyWrap = JPanel(BorderLayout(0, 2))
        bodyWrap.add(JLabel("Request Body:"), BorderLayout.NORTH)
        self._bodyArea = JTextArea(15, 60)
        self._bodyArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._bodyArea.setLineWrap(True)
        self._bodyArea.setWrapStyleWord(True)
        self._bodyArea.setEditable(editable)
        # Focus listener removed to prevent automatically rewriting float formatting (e.g. 12.00 to 12.0)
        bodyScroll = JScrollPane(self._bodyArea)
        bodyScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bodyWrap.add(bodyScroll, BorderLayout.CENTER)

        # Fix: give bodyWrap a minimum size so JSplitPane can never collapse it to zero
        bodyWrap.setMinimumSize(Dimension(0, 80))

        outputWrap = JPanel(BorderLayout(0, 2))
        outputWrap.setMinimumSize(Dimension(0, 60))

        # Header row: label on left, checkbox on right
        outputHeader = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        self._outputLabel = JLabel("Hash Output: ")
        outputHeader.add(self._outputLabel)
        self._autoEncryptChk = JCheckBox("Auto-encrypt on edit", True)
        self._autoEncryptChk.setToolTipText(
            "When checked: editing the decrypted text automatically re-encrypts it back into the request body"
        )
        self._autoEncryptChk.setVisible(False)  # hidden until Crypto tab is selected
        outputHeader.add(self._autoEncryptChk)
        outputWrap.add(outputHeader, BorderLayout.NORTH)

        self._hashOutput = JTextArea(3, 60)
        self._hashOutput.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._hashOutput.setEditable(False)
        self._hashOutput.setLineWrap(True)
        self._hashOutput.setWrapStyleWord(True)
        outputScroll = JScrollPane(self._hashOutput)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        outputScroll.setPreferredSize(Dimension(0, 70))
        outputWrap.add(outputScroll, BorderLayout.CENTER)

        # ---- Debounce timer for auto-encrypt (fires 800 ms after last keystroke) ----
        self._cryptoAutoMode = False
        _outerRef = self
        class _DebounceAction(ActionListener):
            def actionPerformed(self, e):
                _outerRef._onAutoEncrypt()
        self._cryptoDebounceTimer = _SwingTimer(_DEBOUNCE_MS, _DebounceAction())
        self._cryptoDebounceTimer.setRepeats(False)

        # Document listener on Output: restart debounce when user edits plaintext
        class _OutputDocListener(DocumentListener):
            def insertUpdate(self, e):  self._trig()
            def removeUpdate(self, e):  self._trig()
            def changedUpdate(self, e): pass
            def _trig(self):
                if _outerRef._cryptoAutoMode:
                    _outerRef._cryptoDebounceTimer.restart()
        self._hashOutput.getDocument().addDocumentListener(_OutputDocListener())

        hcSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, bodyWrap, outputWrap)
        hcSplit.setResizeWeight(0.8)
        hashCryptoCard.add(hcSplit, BorderLayout.CENTER)

        # ---- Card 2: Key Finder - Parsed Fields + Results ----
        kfCard = JPanel(BorderLayout(0, 4))

        parsedWrap = JPanel(BorderLayout(0, 2))
        parsedWrap.add(JLabel("Parsed Fields (key: value):"), BorderLayout.NORTH)
        self._inlineKfParsedArea = JTextArea(8, 30)
        self._inlineKfParsedArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._inlineKfParsedArea.setEditable(True)
        self._inlineKfParsedArea.setLineWrap(True)
        parsedWrap.add(JScrollPane(self._inlineKfParsedArea), BorderLayout.CENTER)

        resultsWrap = JPanel(BorderLayout(0, 2))
        resultsWrap.add(JLabel("Results:"), BorderLayout.NORTH)
        self._inlineKfResultArea = JTextArea(8, 30)
        self._inlineKfResultArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._inlineKfResultArea.setEditable(False)
        self._inlineKfResultArea.setLineWrap(True)
        resultsWrap.add(JScrollPane(self._inlineKfResultArea), BorderLayout.CENTER)

        kfSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, parsedWrap, resultsWrap)
        kfSplit.setResizeWeight(0.4)
        kfCard.add(kfSplit, BorderLayout.CENTER)

        # ---- Card 3: AppSetting info - shows saved config for current setting ----
        settingCard = JPanel(BorderLayout(0, 6))
        settingCard.setBorder(EmptyBorder(6, 6, 6, 6))
        self._settingInfoArea = JTextArea()
        self._settingInfoArea.setEditable(False)
        self._settingInfoArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._settingInfoArea.setLineWrap(False)
        self._settingInfoArea.setText("(no app setting matched for this request)")
        settingCard.add(JScrollPane(self._settingInfoArea), BorderLayout.CENTER)

        # ---- Card 4: Timestamp ----
        timestampCard = JPanel(BorderLayout(0, 6))
        timestampCard.setBorder(EmptyBorder(6, 6, 6, 6))
        
        tsWrap = JPanel(BorderLayout(0, 2))
        tsWrap.add(JLabel("Timestamp Output:"), BorderLayout.NORTH)
        
        self._inlineTimestampOutputArea = JTextArea()
        self._inlineTimestampOutputArea.setEditable(False)
        self._inlineTimestampOutputArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._inlineTimestampOutputArea.setLineWrap(True)
        self._inlineTimestampOutputArea.setWrapStyleWord(True)
        tsWrap.add(JScrollPane(self._inlineTimestampOutputArea), BorderLayout.CENTER)
        
        timestampCard.add(tsWrap, BorderLayout.CENTER)

        centerPanel.add(hashCryptoCard, "hashcrypto")
        centerPanel.add(kfCard,         "keyfinder")
        centerPanel.add(settingCard,    "setting")
        centerPanel.add(timestampCard,  "timestamp")
        self._panel.add(centerPanel, BorderLayout.CENTER)

        # Switch cards + auto-decrypt/parse when tabs change
        _outer = self
        from javax.swing.event import ChangeListener as _CL
        class _TabListener(_CL):
            def stateChanged(self, e):
                try:
                    idx = _outer._configTabs.getSelectedIndex()
                    if idx == 2:  # Key Finder
                        _outer._outputLabel.setText("Hash Output: ")
                        _outer._autoEncryptChk.setVisible(False)
                        _outer._cryptoAutoMode = False
                        _outer._cryptoDebounceTimer.stop()
                        _outer._hashOutput.setEditable(False)
                        _outer._hashOutput.setText(_outer._lastHashText)
                        _outer._cardLayout.show(centerPanel, "keyfinder")
                        _outer._onInlineKfParse()
                    elif idx == 3:  # AppSetting tab
                        _outer._outputLabel.setText("Hash Output: ")
                        _outer._autoEncryptChk.setVisible(False)
                        _outer._cryptoAutoMode = False
                        _outer._cryptoDebounceTimer.stop()
                        _outer._hashOutput.setEditable(False)
                        _outer._hashOutput.setText(_outer._lastHashText)
                        _outer._cardLayout.show(centerPanel, "setting")
                        _outer._onSettingTabFocus()
                    elif idx == 4:  # Timestamp tab
                        _outer._outputLabel.setText("Hash Output: ")
                        _outer._autoEncryptChk.setVisible(False)
                        _outer._cryptoAutoMode = False
                        _outer._cryptoDebounceTimer.stop()
                        _outer._hashOutput.setEditable(False)
                        _outer._hashOutput.setText(_outer._lastHashText)
                        _outer._cardLayout.show(centerPanel, "timestamp")
                    else:
                        _outer._cardLayout.show(centerPanel, "hashcrypto")
                        if idx == 1:  # Crypto tab
                            _outer._outputLabel.setText("Crypto Output: ")
                            _outer._autoEncryptChk.setVisible(True)
                            _outer._onAutoDecrypt()
                        else:  # Hash tab (idx == 0)
                            try:
                                mode = str(_outer._extender._activeOutputCombo.getSelectedItem())
                            except Exception:
                                mode = "Hash"
                            if mode == "Crypto":
                                _outer._outputLabel.setText("Crypto Output: ")
                                _outer._autoEncryptChk.setVisible(True)
                                _outer._onAutoDecrypt()
                            else:
                                _outer._outputLabel.setText("Hash Output: ")
                                _outer._autoEncryptChk.setVisible(False)
                                _outer._cryptoAutoMode = False
                                _outer._cryptoDebounceTimer.stop()
                                _outer._hashOutput.setEditable(False)
                                # Restore last hash result so crypto output doesn't bleed in
                                _outer._hashOutput.setText(_outer._lastHashText)
                except Exception:
                    pass
        configTabs.addChangeListener(_TabListener())

        # Sync config fields from the main tab if available
        self._syncFromMainTab()

    def _syncFromMainTab(self):
        """Copy config values from the main HashGen tab to this inline tab."""
        try:
            ext = self._extender
            # --- Hash tab ---
            mainAlgo = ext._algoCombo.getSelectedItem()
            if mainAlgo:
                self._algoCombo.setSelectedItem(mainAlgo)
            passcode = ext._passcodeField.getText()
            if passcode:
                self._passcodeField.setText(passcode)
            main_pairs = ext._customDataPanel.getPairs()
            if any(main_pairs.values()):
                self._customDataPanel.setPairs(main_pairs)
            mainKeys = ext._keysOrderField.getText().strip()
            if mainKeys and not self._keysUserEdited:
                self._keysField.setText(mainKeys)
            mainHashField = ext._mainHashFieldName.getText().strip()
            if mainHashField:
                self._hashFieldName.setText(mainHashField)
            # --- Crypto tab ---
            try:
                mainCryptoAlgo = ext._cryptoAlgoCombo.getSelectedItem()
                if mainCryptoAlgo:
                    self._inlineCryptoAlgo.setSelectedItem(mainCryptoAlgo)
                # Set key/iv/field BEFORE mode so the mode-change listener fires
                # with the key already populated (avoids spurious "Key is required")
                cryptoKey = ext._cryptoKeyField.getText()
                if cryptoKey:
                    self._inlineCryptoKey.setText(cryptoKey)
                cryptoIv = ext._cryptoIvField.getText()
                if cryptoIv:
                    self._inlineCryptoIv.setText(cryptoIv)
                mainCryptoField = ext._mainCryptoField.getText().strip()
                if mainCryptoField:
                    self._inlineCryptoField.setText(mainCryptoField)
                # Do NOT sync mode — it is managed automatically by auto-decrypt/encrypt
            except Exception as e:
                print("[CipherKit] Sync crypto error: %s" % str(e))
        except Exception as e:
            print("[CipherKit] Sync error: %s" % str(e))

    def _tryLoadAppSetting(self):
        """Try to auto-load an app setting matching the current request URL path.
        Returns True if a setting was loaded, False otherwise."""
        try:
            path = getattr(self, '_requestPath', '')
            if not path:
                return False
            app_name, app, pattern, ep = self._extender.app_setting_manager.find_by_url(path)
            if not app:
                return False
            self._applyAppSettingToInlineUI(app, ep)
            # Update AppSetting tab UI
            try:
                self._inlineSettingCombo.setSelectedItem(app_name)
                self._inlineSettingStatus.setText("Auto-loaded: %s / %s" % (app_name, pattern))
                self._inlineUrlLabel.setText(getattr(self, '_requestPath', ''))
                if ep:
                    self._inlineEpKeysField.setText(ep.get("keys_order", ""))
            except Exception:
                pass
            print("[CipherKit] Auto-loaded app setting: %s / %s" % (app_name, pattern))
            return True
        except Exception as e:
            print("[CipherKit] AppSetting auto-load error: %s" % str(e))
            return False

    def _applyAppSettingToInlineUI(self, app, ep=None):
        """Apply app-level setting config + optional endpoint to all inline UI fields."""
        if app.get("algorithm"):
            self._algoCombo.setSelectedItem(app["algorithm"])
        if "secret" in app:
            self._passcodeField.setText(app["secret"])
        if app.get("custom_data"):
            self._customDataPanel.setPairs(app["custom_data"])
        if "hash_field" in app:
            self._hashFieldName.setText(app["hash_field"])
        c = app.get("crypto", {})
        if c.get("algorithm"):
            self._inlineCryptoAlgo.setSelectedItem(c["algorithm"])
        if "key" in c:
            self._inlineCryptoKey.setText(c["key"])
        if "iv" in c:
            self._inlineCryptoIv.setText(c["iv"])
        if "field" in c:
            self._inlineCryptoField.setText(c["field"])
        # mode is managed automatically — do not set here
        if ep and "keys_order" in ep:
            self._keysField.setText(ep["keys_order"])
            self._keysUserEdited = True

    def _onKeysManualEdit(self):
        """Mark that the user has manually edited the keys order field."""
        self._keysUserEdited = True

    def _updateInlinePasscodeState(self):
        """Dim/enable the Secret field based on the selected algo's requires_key flag."""
        try:
            name    = str(self._algoCombo.getSelectedItem())
            snippet = self._extender.snippet_manager.get_snippet(name)
            needs   = True
            if snippet:
                needs = snippet.get("requires_key", True)
            gray  = Color(160, 160, 160)
            black = Color(0, 0, 0)
            if needs:
                self._passcodeField.setEditable(True)
                self._passcodeField.setForeground(black)
                self._passcodeLbl.setForeground(black)
            else:
                self._passcodeField.setEditable(False)
                self._passcodeField.setForeground(gray)
                self._passcodeField.setText("")
                self._passcodeLbl.setForeground(gray)
        except Exception:
            pass

    def _onInlineKfParse(self, event=None):
        """Parse the body textarea into the inline Key Finder parsed fields."""
        from collections import OrderedDict
        body = self._bodyArea.getText().strip()
        fmt  = str(self._inlineKfFormatCombo.getSelectedItem())
        try:
            pairs = OrderedDict()
            if fmt == "JSON":
                data = json.loads(body)
                if not isinstance(data, dict):
                    self._inlineKfParsedArea.setText("(JSON is not an object)")
                    return
                for k, v in data.items():
                    pairs[str(k)] = str(v)
            else:
                for part in body.split("&"):
                    if "=" in part:
                        k, _, v = part.partition("=")
                        pairs[k.strip()] = v.strip()
            if not pairs:
                self._inlineKfParsedArea.setText("(no fields found)")
                return
            self._inlineKfParsedArea.setText("\n".join("%s: %s" % (k, v) for k, v in pairs.items()))
        except Exception as e:
            self._inlineKfParsedArea.setText("Parse error: %s" % str(e))

    def _onInlineKfFind(self, event=None):
        """Find key order from inline Key Finder fields using DFS backtracking."""
        try:
            from collections import OrderedDict
            known = str(self._inlineKfKnownArea.getText().strip())
            if not known:
                self._inlineKfResultArea.setText("Please enter the known concatenated string.")
                return

            pairs = OrderedDict()
            # Parsed fields
            for line in self._inlineKfParsedArea.getText().strip().splitlines():
                line = line.strip()
                if ":" in line:
                    k, _, v = line.partition(":")
                    pairs[k.strip()] = v.strip()
            # Extra Fields panel (CompactCustomDataPanel)
            for k, v in self._inlineKfAdditionalPanel.getPairs().items():
                if k:
                    pairs[k] = v

            if not pairs:
                self._inlineKfResultArea.setText("No fields found. Click Parse Body first.")
                return

            # Backtracking DFS search
            matches = []
            total_visited = [0]
            values = {k: str(v) for k, v in pairs.items()}
            
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
            
            dfs((), list(pairs.keys()), known)

            if not matches:
                lines = ["No match found.", ""]
                # Show which field values appear in the known string
                found_keys = [(k, v) for k, v in pairs.items() if v and str(v) in known]
                if found_keys:
                    lines.append("Values found in known string:")
                    for k, v in found_keys:
                        lines.append("  %s : %s" % (k, v))
                    lines.append("")
                # Find segments in the known string not covered by any field value
                remaining = known
                for _, v in found_keys:
                    remaining = remaining.replace(str(v), "\x00", 1)
                unknown_parts = [p for p in remaining.split("\x00") if p]
                if unknown_parts:
                    lines.append("Unknown segment(s) not from any field:")
                    for part in unknown_parts:
                        lines.append("  %s" % part)
                self._inlineKfResultArea.setText("\n".join(lines))
            else:
                lines = []
                for i, perm in enumerate(matches, 1):
                    if len(matches) > 1:
                        lines.append("Match #%d:" % i)
                    lines.append("Key order : %s" % ", ".join(perm))
                    lines.append("Concat    : %s" % "".join(str(pairs[k]) for k in perm))
                    if i < len(matches):
                        lines.append("")
                if len(matches) >= 100 or total_visited[0] >= 10000:
                    lines.append("")
                    lines.append("(Note: search was capped at 100 matches to optimize performance)")
                self._inlineKfResultArea.setText("\n".join(lines))
        except Exception as e:
            self._inlineKfResultArea.setText("Error: %s\n%s" % (str(e), traceback.format_exc()))

    # --- IMessageEditorTab interface ---

    def getTabCaption(self):
        return "CipherKit"

    def getUiComponent(self):
        return self._panel

    def _resetEditorState(self, content=None):
        self._currentMessage = content
        self._headerBytes = None
        self._contentType = ""
        self._requestPath = ""
        self._bodyArea.setText("")
        self._hashOutput.setEditable(False)
        self._hashOutput.setText("")
        self._cryptoAutoMode = False
        try:
            self._cryptoDebounceTimer.stop()
        except Exception:
            pass

    def isEnabled(self, content, isRequest):
        if not isRequest or content is None:
            return False
        try:
            analyzed = self._helpers.analyzeRequest(content)
            bodyOffset = analyzed.getBodyOffset()
            body = self._helpers.bytesToString(content[bodyOffset:])
            return len(body.strip()) > 0
        except:
            return False

    def setMessage(self, content, isRequest):
        self._isRequestContext = bool(isRequest)
        if content is None or not isRequest:
            self._resetEditorState(content)
            return

        try:
            self._currentMessage = content
            analyzed = self._helpers.analyzeRequest(content)
            bodyOffset = analyzed.getBodyOffset()

            self._headerBytes = content[:bodyOffset]

            # Extract Content-Type from headers for body parsing
            self._contentType = ""
            for h in analyzed.getHeaders():
                if h.lower().startswith("content-type:"):
                    self._contentType = h[len("content-type:"):].strip()
                    break

            body = self._helpers.bytesToString(content[bodyOffset:])

            # Display the body exactly as it is in the request without pretty-printing,
            # which would alter floating point numbers (e.g. converting 12.00 to 12.0)
            self._bodyArea.setText(body)
            self._bodyArea.setCaretPosition(0)

            # Extract URL path for app setting matching
            self._requestPath = ""
            try:
                self._requestPath = analyzed.getUrl().getPath()
            except:
                pass

            # Try auto-load an app setting matching this URL path
            setting_loaded = self._tryLoadAppSetting()

            # Only auto-extract keys if no setting was loaded and user hasn't manually edited
            if not setting_loaded and not self._keysUserEdited:
                self._tryExtractKeys()

            # Sync remaining config from main tab (only fields not set by app setting)
            if not setting_loaded:
                self._syncFromMainTab()

            # If the Crypto tab is already selected, re-run auto-decrypt now that
            # key/iv have been populated (the mode-change listener may have fired
            # before the key was set, producing a spurious "Key is required" error)
            try:
                if self._configTabs.getSelectedIndex() == 1:
                    self._onAutoDecrypt()
            except Exception:
                pass
        except Exception as e:
            self._resetEditorState(content)
            print("[CipherKit] Inline tab setMessage error: %s" % str(e))
            print(traceback.format_exc())
            return

    def getMessage(self):
        if self._currentMessage is None or not self._isRequestContext:
            return self._currentMessage

        try:
            body_str = self._bodyArea.getText()
            body_bytes = self._helpers.stringToBytes(body_str)

            analyzed = self._helpers.analyzeRequest(self._currentMessage)
            headers = analyzed.getHeaders()
            return self._helpers.buildHttpMessage(headers, body_bytes)
        except Exception as e:
            print("[CipherKit] Inline tab getMessage error: %s" % str(e))
            print(traceback.format_exc())
            return self._currentMessage

    def isModified(self):
        if self._currentMessage is None or not self._isRequestContext:
            return False
        try:
            analyzed = self._helpers.analyzeRequest(self._currentMessage)
            bodyOffset = analyzed.getBodyOffset()
            originalBody = self._helpers.bytesToString(self._currentMessage[bodyOffset:]).strip()
            currentBody = self._bodyArea.getText().strip()
            return originalBody != currentBody
        except Exception as e:
            print("[CipherKit] Inline tab isModified error: %s" % str(e))
            print(traceback.format_exc())
            return False

    def getSelectedData(self):
        selected = self._bodyArea.getSelectedText()
        if selected:
            return self._helpers.stringToBytes(selected)
        return None

    # --- Actions ---

    def _onGenerate(self, event=None):
        result, debug_log = self._computeHash()
        try:
            crypto_output_mode = str(self._extender._activeOutputCombo.getSelectedItem()) == "Crypto"
        except Exception:
            crypto_output_mode = False
        if not crypto_output_mode:
            text = "[HASH] " + str(result)
            self._lastHashText = text
            self._hashOutput.setText(text)

    def _onGenerateAndInject(self, event=None):
        result, debug_log = self._computeHash()
        # Determine if Hash tab output is in Crypto mode (output area shows decrypted text)
        try:
            crypto_output_mode = str(self._extender._activeOutputCombo.getSelectedItem()) == "Crypto"
        except Exception:
            crypto_output_mode = False
        if result and not str(result).startswith("Error"):
            body_str = self._bodyArea.getText().strip()
            try:
                ct = getattr(self, '_contentType', '')
                data = parse_body(body_str, ct)
                field_name = self._hashFieldName.getText().strip() or "hash"
                data[field_name] = str(result)
                serialized = serialize_body(data, body_str, ct)
                self._bodyArea.setText(serialized)
                self._bodyArea.setCaretPosition(0)
                # Only update the output area when NOT in Crypto mode
                if not crypto_output_mode:
                    text = "[HASH] " + str(result)
                    self._lastHashText = text
                    self._hashOutput.setText(text)
            except Exception as e:
                self._hashOutput.setText("Error injecting hash: %s" % str(e))
        else:
            if not crypto_output_mode:
                self._lastHashText = str(result)
                self._hashOutput.setText(str(result))

    def _onInlineSaveSetting(self, event=None):
        """Save current config as an app setting + endpoint.
        Reads the app name from the combo and keys order from the AppSetting tab field."""
        path = getattr(self, '_requestPath', '')

        # App name: use combo selection or ask
        selected_combo = str(self._inlineSettingCombo.getSelectedItem())
        existing = self._extender.app_setting_manager.get_all_names()

        if selected_combo and selected_combo != "(none)":
            app_name = selected_combo
        else:
            choices = existing + ["[ New app... ]"]
            app_name = JOptionPane.showInputDialog(
                self._panel, "App setting name (select existing or type new):", "Save Endpoint",
                JOptionPane.PLAIN_MESSAGE, None,
                choices if choices else None,
                existing[0] if existing else ""
            )
            if not app_name or not str(app_name).strip():
                return
            app_name = str(app_name).strip()

        if app_name == "[ New app... ]":
            app_name = JOptionPane.showInputDialog(
                self._panel, "New app name:", "Save Endpoint",
                JOptionPane.PLAIN_MESSAGE, None, None, ""
            )
            if not app_name or not str(app_name).strip():
                return
            app_name = str(app_name).strip()

        # URL pattern: pre-fill from AppSetting tab URL label or current path
        pattern = JOptionPane.showInputDialog(
            self._panel, "URL pattern for this endpoint (e.g. /api/user):",
            "URL Pattern", JOptionPane.PLAIN_MESSAGE, None, None, path
        )
        pattern = str(pattern).strip() if pattern else ""

        # Keys order: prefer AppSetting tab field (user may have edited it there)
        try:
            keys_order = self._inlineEpKeysField.getText().strip() or self._keysField.getText().strip()
        except Exception:
            keys_order = self._keysField.getText().strip()

        # Save app-level config (algorithm, secret, crypto - shared across endpoints)
        app_data = {
            "algorithm":   str(self._algoCombo.getSelectedItem()),
            "secret":      self._passcodeField.getText(),
            "custom_data": self._customDataPanel.getPairs(),
            "hash_field":  self._hashFieldName.getText().strip() or "hash",
            "crypto": {
                "mode":      str(self._inlineCryptoMode.getSelectedItem()),
                "algorithm": str(self._inlineCryptoAlgo.getSelectedItem()),
                "key":       self._inlineCryptoKey.getText(),
                "iv":        self._inlineCryptoIv.getText(),
                "field":     self._inlineCryptoField.getText().strip() or "data",
            },
        }
        self._extender.app_setting_manager.save_app(app_name, app_data)
        if pattern:
            self._extender.app_setting_manager.save_endpoint(app_name, pattern, keys_order)

        self._refreshInlineSettingCombo()
        self._inlineSettingCombo.setSelectedItem(app_name)
        try:
            self._extender._refreshSettingCombo()
        except:
            pass
        label = "%s%s" % (app_name, (" / " + pattern) if pattern else "")
        try:
            self._inlineSettingStatus.setText("Saved: %s" % label)
        except Exception:
            pass
        self._hashOutput.setText("Saved: %s" % label)
        print("[CipherKit] AppSetting saved: %s" % label)

    def _onInlineLoadSetting(self, event=None):
        """Manually load the selected app setting into all config fields."""
        name = str(self._inlineSettingCombo.getSelectedItem())
        if name == "(none)":
            return
        app = self._extender.app_setting_manager.get_app(name)
        if not app:
            return
        try:
            # Find matching endpoint for current URL
            path = getattr(self, '_requestPath', '')
            matched_ep = None
            for pat, ep in app.get("endpoints", {}).items():
                if pat and pat in path:
                    matched_ep = ep
                    break
            self._applyAppSettingToInlineUI(app, matched_ep)
            self._hashOutput.setText("Loaded setting: %s" % name)
            print("[CipherKit] Manually loaded setting: %s" % name)
        except Exception as e:
            print("[CipherKit] Load setting error: %s" % str(e))

    @staticmethod
    def _refill_setting_combo(combo, names):
        """Repopulate an AppSetting JComboBox, restoring prior selection if still present."""
        current = str(combo.getSelectedItem())
        combo.removeAllItems()
        combo.addItem("(none)")
        for n in names:
            combo.addItem(n)
        if current and current != "(none)":
            combo.setSelectedItem(current)

    def _refreshInlineSettingCombo(self):
        """Refresh the inline setting combo box with current app names."""
        try:
            self._refill_setting_combo(
                self._inlineSettingCombo,
                self._extender.app_setting_manager.get_all_names()
            )
        except Exception as e:
            print("[CipherKit] Refresh inline combo error: %s" % str(e))

    def _onSettingTabFocus(self):
        """Populate the AppSetting tab fields and info area when switching to it."""
        try:
            path = getattr(self, '_requestPath', '')
            self._inlineUrlLabel.setText(path or "(no request loaded)")
            self._inlineEpKeysField.setText(self._keysField.getText())
            self._refreshInlineSettingInfo()
        except Exception as e:
            print("[CipherKit] AppSetting tab focus error: %s" % str(e))

    def _refreshInlineSettingInfo(self):
        """Refresh the setting info text area with the selected app's saved config."""
        try:
            name = str(self._inlineSettingCombo.getSelectedItem())
            if name == "(none)":
                self._settingInfoArea.setText("(no setting selected - pick one from the dropdown above)")
                return
            app = self._extender.app_setting_manager.get_app(name)
            if not app:
                self._settingInfoArea.setText("(setting '%s' not found)" % name)
                return
            path = getattr(self, '_requestPath', '')
            lines = []
            lines.append("App Setting : %s" % name)
            lines.append("Current URL: %s" % (path or "(none)"))
            lines.append("")
            lines.append("Shared Config")
            lines.append("-" * 40)
            lines.append("  Algorithm : %s" % app.get("algorithm", ""))
            lines.append("  Secret    : %s" % app.get("secret", ""))
            lines.append("  Hash Field: %s" % app.get("hash_field", ""))
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
                lines.append("-" * 40)
                for pat, ep in endpoints.items():
                    matched = " < matched" if pat and pat in path else ""
                    lines.append("  %-28s  %s%s" % (pat, ep.get("keys_order", ""), matched))
            else:
                lines.append("")
                lines.append("No endpoints saved yet.")
                lines.append("Set keys order in the Hash tab, then click Save Endpoint.")
            self._settingInfoArea.setText("\n".join(lines))
            self._settingInfoArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] Setting info refresh error: %s" % str(e))

    def _onInlineDeleteSetting(self, event=None):
        """Delete the selected app setting."""
        name = str(self._inlineSettingCombo.getSelectedItem())
        if name == "(none)":
            return
        confirm = JOptionPane.showConfirmDialog(
            self._panel, "Delete app setting '%s' and all its endpoints?" % name,
            "Delete Setting", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self._extender.app_setting_manager.delete_app(name)
            self._refreshInlineSettingCombo()
            try:
                self._extender._refreshSettingCombo()
            except:
                pass
            self._inlineSettingStatus.setText("Deleted: %s" % name)
            print("[CipherKit] AppSetting deleted: %s" % name)

    def _onCryptoRun(self, event=None):
        """Run AES-CBC encrypt/decrypt on the named body field and show result."""
        try:
            result = self._computeCrypto()
            self._hashOutput.setText("[CRYPTO] " + str(result))
        except Exception as e:
            self._hashOutput.setText("[CRYPTO] Error: %s" % str(e))

    def _onAutoDecrypt(self):
        """Auto-decrypt the named field when switching to Crypto tab (Decrypt mode only).
        Silently clears the output and does nothing when required params are missing."""
        self._cryptoAutoMode = False
        self._cryptoDebounceTimer.stop()
        # Always force Decrypt — mode is managed automatically, never set externally
        self._inlineCryptoMode.setSelectedItem("Decrypt")
        # Silently skip if required parameters are not yet filled in
        key   = self._inlineCryptoKey.getText().strip()
        field = self._inlineCryptoField.getText().strip()
        if not key or not field:
            self._hashOutput.setEditable(False)
            self._hashOutput.setText("")
            return
        try:
            result = self._computeCrypto()
            if result and not str(result).startswith("Error"):
                self._hashOutput.setEditable(True)
                self._hashOutput.setText(str(result))
                self._cryptoAutoMode = True
                self._lastEncryptedPlaintext = None  # fresh decrypt — allow next edit to encrypt
            else:
                self._hashOutput.setEditable(False)
                self._hashOutput.setText("")
        except Exception as e:
            self._hashOutput.setEditable(False)
            self._hashOutput.setText("")
            print("[CipherKit] Auto-decrypt error: %s" % str(e))

    def _onAutoEncrypt(self):
        """Debounced: encrypt the plaintext in Output and inject back into the body field."""
        if not self._cryptoAutoMode:
            return
        # Check local auto-encrypt checkbox (Crypto tab only; Hash tab inherits the state)
        if not self._autoEncryptChk.isSelected():
            return
        # Check global session checkbox in main tab
        try:
            if not self._extender._globalAutoEncryptChk.isSelected():
                return
        except Exception:
            pass
        # Silently skip if required parameters are missing
        key = self._inlineCryptoKey.getText().strip()
        if not key:
            return
        try:
            plaintext = self._hashOutput.getText()
            if not plaintext:
                return
            # Skip if plaintext hasn't changed since the last encrypt (prevents loops)
            if plaintext == getattr(self, '_lastEncryptedPlaintext', None):
                return
            iv    = self._inlineCryptoIv.getText().strip() or None
            field = self._inlineCryptoField.getText().strip() or "data"
            algo    = str(self._inlineCryptoAlgo.getSelectedItem()) if hasattr(self, '_inlineCryptoAlgo') else "AES-CBC-128"
            snippet = self._extender.crypto_snippet_manager.get_snippet(algo)
            if snippet:
                encrypted = CryptoSnippetEngine.execute(snippet, "Encrypt", plaintext, key, iv or "")
            else:
                encrypted = AesCbcEngine.encrypt(plaintext, key, iv)
            body_str   = self._bodyArea.getText().strip()
            ct         = getattr(self, '_contentType', '')
            data       = parse_body(body_str, ct)
            data[field] = str(encrypted)
            serialized  = serialize_body(data, body_str, ct)
            self._lastEncryptedPlaintext = plaintext  # guard against re-encrypt loop
            # Update body without disrupting caret
            self._bodyArea.setText(serialized)
            self._bodyArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] Auto-encrypt error: %s" % str(e))

    def _computeCrypto(self):
        """Read crypto config, read field value from body, run selected algorithm."""
        mode  = str(self._inlineCryptoMode.getSelectedItem())
        key   = self._inlineCryptoKey.getText()
        iv    = self._inlineCryptoIv.getText().strip() or ""
        field = self._inlineCryptoField.getText().strip() or "data"
        algo  = str(self._inlineCryptoAlgo.getSelectedItem()) if hasattr(self, '_inlineCryptoAlgo') else "AES-CBC-128"

        if not key:
            return "Error: Crypto Key is required."

        body_str = self._bodyArea.getText().strip()
        ct       = getattr(self, '_contentType', '')
        data     = parse_body(body_str, ct)

        field_value = ""
        if isinstance(data, dict) and field in data:
            field_value = str(data[field])
        elif body_str:
            field_value = body_str

        if not field_value:
            return "Error: Field '%s' not found or empty in body." % field

        # Dispatch through snippet system; fall back to built-in AesCbcEngine
        snippet = self._extender.crypto_snippet_manager.get_snippet(algo)
        if snippet:
            return CryptoSnippetEngine.execute(snippet, mode, field_value, key, iv)
        else:
            if mode == "Encrypt":
                return AesCbcEngine.encrypt(field_value, key, iv or None)
            else:
                return AesCbcEngine.decrypt(field_value, key, iv or None)

    def _computeHash(self):
        name = self._algoCombo.getSelectedItem()
        if not name:
            return "Error: No algorithm selected.", ""

        snippet = self._extender.snippet_manager.get_snippet(str(name))
        if not snippet:
            return "Error: Snippet '%s' not found." % name, ""

        try:
            body_str = self._bodyArea.getText().strip()
            ct = getattr(self, '_contentType', '')
            payload = parse_body(body_str, ct)
            if not payload:
                return "Error: Body could not be parsed or is empty.", ""
            passcode = self._passcodeField.getText()
            custom_data = self._customDataPanel.getPairs()

            keys_str = self._keysField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            return CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, custom_data, key_order
            )
        except Exception as e:
            return "Error: %s" % str(e), traceback.format_exc()

    def _tryExtractKeys(self):
        """Auto-extract keys from body (any format). Only if user hasn't manually edited."""
        try:
            body_str = self._bodyArea.getText().strip()
            if not body_str:
                return
            ct = getattr(self, '_contentType', '')
            data = parse_body(body_str, ct)
            if isinstance(data, dict) and data:
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysField.getText().strip()
                if current != new_keys_str:
                    self._keysUserEdited = False
                    self._keysField.setText(new_keys_str)
        except:
            pass

    def _tryFormatJson(self):
        """Pretty-print body only when it is valid JSON."""
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

    def _onInlineGetTimestamp(self, event=None):
        import time
        ms = int(time.time() * 1000)
        val = str(ms)
        self._inlineTimestampOutputArea.setText(val)
        if self._inlineTsAutoCopyChk.isSelected():
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(val), None)

    def _onInlineCopyTimestamp(self, event=None):
        txt = self._inlineTimestampOutputArea.getText().strip()
        if txt:
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(txt), None)


# =============================================================================
# Burp Suite Extension Entry Point

# -*- coding: utf-8 -*-
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

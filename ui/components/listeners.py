# -*- coding: utf-8 -*-
from javax.swing.event import DocumentListener


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

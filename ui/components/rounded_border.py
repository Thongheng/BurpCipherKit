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

class RoundedBorder(AbstractBorder):
    """A rounded-corner border for JTextField / JScrollPane / JPanel."""

    def __init__(self, radius=8, color=Color(180, 180, 180), thickness=1):
        self._radius    = radius
        self._color     = color
        self._thickness = thickness

    def paintBorder(self, c, g, x, y, w, h):
        g2 = g.create()
        g2.setRenderingHint(
            RenderingHints.KEY_ANTIALIASING,
            RenderingHints.VALUE_ANTIALIAS_ON
        )
        g2.setColor(self._color)
        from java.awt import BasicStroke
        g2.setStroke(BasicStroke(self._thickness))
        g2.drawRoundRect(
            x + self._thickness // 2,
            y + self._thickness // 2,
            w - self._thickness,
            h - self._thickness,
            self._radius, self._radius
        )
        g2.dispose()

    def getBorderInsets(self, c, insets=None):
        pad = self._radius // 2 + 2
        if insets is not None:
            insets.top = pad; insets.left = pad
            insets.bottom = pad; insets.right = pad
            return insets
        return Insets(pad, pad, pad, pad)

    def isBorderOpaque(self):
        return False


def _roundedCompound(radius=8, padding=4, color=Color(180, 180, 180)):
    """Convenience: RoundedBorder + inner EmptyBorder padding."""
    return BorderFactory.createCompoundBorder(
        RoundedBorder(radius, color),
        EmptyBorder(padding, padding, padding, padding)
    )


# =============================================================================
# UI Helper: Custom Data Fields Manager (key:value rows)

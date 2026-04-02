# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os, sys, hashlib, hmac, base64, time, traceback, itertools

def _safe_encode(value):
    """Return a UTF-8 bytes object from str or bytes, handling non-ASCII safely."""
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        value = str(value)
    return value.encode('utf-8')

# =============================================================================
# Constants
# =============================================================================
_DEBOUNCE_MS      = 800   # ms delay before auto-encrypt fires
_MAX_KF_FIELDS    = 10    # max fields for key finder brute-force
_DEFAULT_DIVIDER  = 320   # default split pane divider position
_MONO_FONT_SIZE   = 12    # monospaced font size for all text areas


# =============================================================================
# Core Logic: Snippet Manager (reused from HashGen.py)

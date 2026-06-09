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


def _extract_request_path(req_info):
    """Extract URL path from IRequestInfo, falling back to parsing headers if getUrl() fails."""
    try:
        url = req_info.getUrl()
        if url:
            path = url.getPath()
            if path:
                return str(path)
    except:
        pass
    try:
        headers = req_info.getHeaders()
        if headers and len(headers) > 0:
            req_line = str(headers[0])
            parts = req_line.split(" ")
            if len(parts) > 1:
                path_part = parts[1]
                if "://" in path_part:
                    from java.net import URL
                    path_part = URL(path_part).getPath()
                if "?" in path_part:
                    path_part = path_part.split("?")[0]
                return str(path_part)
    except:
        pass
    return ""


# =============================================================================
# Core Logic: Snippet Manager (reused from HashGen.py)

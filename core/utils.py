# -*- coding: utf-8 -*-
from __future__ import print_function

def _safe_text(value):
    """Return Unicode text without Jython's implicit ASCII conversion."""
    try:
        text_type = unicode
    except NameError:
        text_type = str

    if isinstance(value, text_type):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except Exception:
            return value.decode('utf-8', 'replace')
    try:
        return text_type(value)
    except Exception:
        return text_type(str(value), 'utf-8', 'replace')

# =============================================================================
# Constants
# =============================================================================
_DEBOUNCE_MS      = 800   # ms delay before auto-encrypt fires
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

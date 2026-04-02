# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os, sys, hashlib, hmac, base64, time, traceback, itertools

from core.utils import _safe_encode

def _get_boundary(content_type):
    """Extract the multipart boundary from a Content-Type header value."""
    if not content_type:
        return None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            return part[len("boundary="):].strip().strip('"')
    return None


def _auto_detect_boundary(body_str):
    """Extract boundary from the first non-empty line of a multipart body.
    The first line is always '--<boundary>', so we strip the leading '--'.
    """
    for line in body_str.splitlines():
        line = line.strip()
        if line.startswith("--") and len(line) > 2:
            return line[2:]  # Strip the leading '--' prefix
    return None


def _try_parse_json(body_str):
    try:
        result = json.loads(body_str)
        if isinstance(result, dict):
            return result
    except:
        pass
    return None


def _try_parse_urlencoded(body_str):
    """Parse application/x-www-form-urlencoded body. Jython-safe."""
    try:
        stripped = body_str.strip()
        # Reject multipart bodies (they start with --boundary)
        if stripped.startswith("--"):
            return None
        result = {}
        for pair in stripped.split("&"):
            pair = pair.strip()
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            # Full URL decode (Bug-3): use Java URLDecoder, fall back to urllib
            try:
                from java.net import URLDecoder
                k = URLDecoder.decode(k, "UTF-8")
                v = URLDecoder.decode(v, "UTF-8")
            except Exception:
                try:
                    import urllib
                    k = urllib.unquote_plus(k)
                    v = urllib.unquote_plus(v)
                except Exception:
                    k = k.replace("+", " ")
                    v = v.replace("+", " ")
            if k:
                result[k] = v
        # Only return if we found key=value pairs (not a JSON-looking string)
        if result and not stripped.startswith("{"):
            return result
    except:
        pass
    return None


def _try_parse_multipart(body_str, content_type):
    """Parse multipart/form-data body using a line-by-line state machine."""
    # Try to get boundary from Content-Type header first, then auto-detect from body
    boundary = _get_boundary(content_type)
    if not boundary:
        boundary = _auto_detect_boundary(body_str)
    if not boundary:
        return None
    try:
        result = {}
        delimiter     = "--" + boundary       # e.g. ------geckoform...
        delimiter_end = "--" + boundary + "--" # final boundary

        # Normalise line endings and split into lines
        lines = body_str.replace("\r\n", "\n").replace("\r", "\n").split("\n")

        # States: 'seek' -> looking for boundary, 'headers' -> reading part headers,
        #         'value' -> reading part value
        state       = "seek"
        current_name  = None
        value_lines   = []
        in_header_block = False

        for line in lines:
            stripped = line.strip()

            if state == "seek":
                if stripped == delimiter or stripped == delimiter_end:
                    state = "headers"
                    current_name = None
                    value_lines  = []
                    in_header_block = True
                continue

            if state == "headers":
                if stripped == "":
                    # Blank line marks end of headers, start of value
                    state = "value"
                else:
                    lower = stripped.lower()
                    if "content-disposition" in lower and "name=" in lower:
                        for seg in stripped.split(";"):
                            seg = seg.strip()
                            if seg.lower().startswith("name="):
                                current_name = seg[5:].strip().strip('"\'')
                continue

            if state == "value":
                if stripped == delimiter or stripped == delimiter_end:
                    # Save current field
                    if current_name is not None:
                        result[current_name] = "\n".join(value_lines).rstrip("\r\n ")
                    # Reset for next part
                    current_name = None
                    value_lines  = []
                    if stripped == delimiter_end:
                        state = "seek"  # done
                    else:
                        state = "headers"
                else:
                    value_lines.append(line)

        # Flush any trailing field (malformed final boundary)
        if state == "value" and current_name is not None:
            result[current_name] = "\n".join(value_lines).rstrip("\r\n ")

        if result:
            return result
    except Exception:
        pass
    return None



def parse_body(body_str, content_type=""):
    """
    Parse an HTTP request body into a dict.
    Supports: application/json, application/x-www-form-urlencoded, multipart/form-data.
    Tries all strategies; content_type just controls priority.
    Returns {} if nothing works.
    """
    if not body_str or not body_str.strip():
        return {}

    ct = (content_type or "").lower().split(";")[0].strip()

    # Decide priority order based on declared Content-Type
    if ct == "application/x-www-form-urlencoded":
        strategies = [_try_parse_urlencoded, _try_parse_json,
                      lambda b: _try_parse_multipart(b, content_type)]
    elif ct == "multipart/form-data":
        strategies = [lambda b: _try_parse_multipart(b, content_type),
                      _try_parse_json, _try_parse_urlencoded]
    else:
        # JSON first (default), then try others as fallback
        strategies = [_try_parse_json, _try_parse_urlencoded,
                      lambda b: _try_parse_multipart(b, content_type)]

    for strategy in strategies:
        try:
            result = strategy(body_str)
            if result:
                return result
        except:
            pass

    return {}


def serialize_body(updated_data, original_body, content_type=""):
    """
    Re-encode updated_data back to the same format as the original body.
    Used by Gen & Inject to write the hash back without changing the format.
    """
    ct = (content_type or "").lower().split(";")[0].strip()

    if ct == "application/x-www-form-urlencoded":
        try:
            return "&".join(
                "{}={}".format(str(k), str(v))
                for k, v in updated_data.items()
            )
        except:
            pass

    if ct == "multipart/form-data":
        # Bug-4: auto-detect boundary from body when header is missing; error instead of silently falling back
        boundary = _get_boundary(content_type)
        if not boundary:
            boundary = _auto_detect_boundary(original_body)
        if boundary:
            try:
                parts = []
                for k, v in updated_data.items():
                    parts.append("--" + boundary)
                    parts.append('Content-Disposition: form-data; name="{}"'.format(k))
                    parts.append("")
                    parts.append(str(v))
                parts.append("--" + boundary + "--")
                parts.append("")
                return "\r\n".join(parts)
            except:
                pass
        else:
            raise ValueError("multipart/form-data body has no boundary; cannot re-serialize safely.")

    # JSON fallback
    try:
        return json.dumps(updated_data, indent=2)
    except:
        return original_body



# =============================================================================
# Core Logic: Crypto Engine

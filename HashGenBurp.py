# -*- coding: utf-8 -*-
# CipherKit - Burp Suite Extension
# Universal Hash & Crypto toolkit for Burp Suite.
# Requires Jython configured in Burp Suite (Extender > Options > Python Environment).

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation,
    IMessageEditorTabFactory, IMessageEditorTab
)

from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JButton, JComboBox, JCheckBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, BorderFactory,
    SwingUtilities, BoxLayout, Box
)
from javax.swing.border import EmptyBorder, TitledBorder, AbstractBorder
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout, Component, GridLayout,
    RenderingHints
)
from java.awt.event import FocusAdapter, ActionListener
from javax.swing.event import DocumentListener
from javax.swing import Timer as _SwingTimer

# Java crypto (always available in Burp's JVM -- no external deps needed)
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec

import json
import os
import sys
import hashlib
import hmac
import base64
import time
import traceback
import itertools


# =============================================================================
# Constants
# =============================================================================
_DEBOUNCE_MS      = 800   # ms delay before auto-encrypt fires
_MAX_KF_FIELDS    = 10    # max fields for key finder brute-force
_DEFAULT_DIVIDER  = 320   # default split pane divider position
_MONO_FONT_SIZE   = 12    # monospaced font size for all text areas


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
            print("[CipherKit] Error loading snippets: %s" % str(e))
            self.snippets = {}

    def save_snippets(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.snippets, f, indent=2)
            return True
        except Exception as e:
            print("[CipherKit] Error saving snippets: %s" % str(e))
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
            "def generate(payload, passcode, custom_data=None, key_order=None):\n"
            "    import hmac\n"
            "    import hashlib\n"
            "\n"
            "    # payload = merged dict of custom_data + request body JSON\n"
            "    # custom_data = dict {key_name: value} - keys are in payload too\n"
            "\n"
            "    # 1. Parse Passcode\n"
            "    if len(passcode) < 16:\n"
            "        raise ValueError(\"PassCode must be at least 16 characters long.\")\n"
            "    iv = passcode[-16:]\n"
            "    key = passcode[:-16]\n"
            "\n"
            "    # 2. Determine Keys to Sign\n"
            "    keys_to_sign = []\n"
            "    if key_order:\n"
            "        keys_to_sign = key_order\n"
            "    else:\n"
            "        keys_to_sign = [k for k in payload.keys() if k != 'hash']\n"
            "\n"
            "    # 3. Concat Values (payload has custom_data keys merged in)\n"
            "    concat_str = \"\"\n"
            "    for k in keys_to_sign:\n"
            "        val = payload.get(k)\n"
            "        if val is None: val = \"\"\n"
            "        concat_str += str(val)\n"
            "\n"
            "    # 4. Create Message\n"
            "    message = iv + concat_str\n"
            "\n"
            "    # 5. Sign\n"
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
# Body Parser Utilities -- JSON / URL-encoded / multipart/form-data
# =============================================================================
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
            # Manual URL decode -- do not rely on urllib in Jython
            k = k.replace("+", " ").replace("%3D", "=").replace("%26", "&")
            v = v.replace("+", " ").replace("%3D", "=").replace("%26", "&")
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
        boundary = _get_boundary(content_type)
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

    # JSON fallback
    try:
        return json.dumps(updated_data, indent=2)
    except:
        return original_body



# =============================================================================
# Core Logic: Crypto Engine
# =============================================================================
class CryptoEngine:
    @staticmethod
    def execute_snippet(snippet_code, payload, passcode, custom_data=None, key_order=None):
        """
        Execute a snippet.
        custom_data: dict of {key_name: value} from the custom data fields.
        The merge_payload is built by combining custom_data + payload so that
        key_order can reference both custom data keys and payload keys.
        Backward compat: if snippet uses old `api_key` str param, first value is passed.
        If a snippet returns a tuple (hash_str, debug_log), the debug_log is shown in the UI.
        """
        local_scope = {}
        global_scope = {
            "hashlib": hashlib,
            "hmac": hmac,
            "base64": base64,
            "json": json,
            "time": time
        }

        # Build merged context: custom_data keys come first, then payload keys
        if custom_data is None:
            custom_data = {}

        # Merged dict for snippets that want a unified lookup
        merged = {}
        merged.update(custom_data)
        merged.update(payload)

        try:
            exec(snippet_code, global_scope, local_scope)

            if "generate" not in local_scope:
                raise ValueError("Snippet must define a 'generate' function.")

            generate_func = local_scope["generate"]

            # Try new signature: (payload, passcode, custom_data_dict, key_order)
            try:
                res = generate_func(merged, passcode, custom_data, key_order)
            except TypeError as te:
                err_msg = str(te)
                if "argument" in err_msg:
                    # Fallback for old snippets using api_key (single string)
                    api_key = list(custom_data.values())[0] if custom_data else ""
                    try:
                        res = generate_func(merged, passcode, api_key, key_order)
                    except TypeError:
                        res = generate_func(merged, passcode, api_key)
                else:
                    raise te
            
            # Unpack if snippet returns a debug log tuple
            if isinstance(res, tuple) and len(res) == 2:
                return res[0], res[1]
            return res, ""

        except Exception as e:
            return "Error: %s\n%s" % (str(e), traceback.format_exc())


# =============================================================================
# AES-CBC-128 Encrypt / Decrypt Engine
# Matches the JS crypto.subtle AES-CBC reference implementation:
#   - Key and IV are UTF-8 encoded strings (16 bytes for AES-128)
#   - If IV is blank/None, the KEY bytes are reused as IV (JS default behaviour)
#   - Ciphertext is Base64 (matches btoa/atob in the JS sample)
#   - Padding: PKCS5 (same as PKCS7, the browser default)
# =============================================================================
class AesCbcEngine:
    ALGORITHM = "AES/CBC/PKCS5Padding"

    @staticmethod
    def _prepare(key_utf8, iv_utf8):
        """Convert UTF-8 key and IV strings to Java byte arrays."""
        key_bytes = key_utf8.encode("UTF-8")
        if iv_utf8 and iv_utf8.strip():
            iv_bytes = iv_utf8.encode("UTF-8")
        else:
            # JS default: if iv is empty/omitted, reuse the key bytes as IV
            iv_bytes = key_bytes
        # Validate lengths (AES-128 = 16 bytes)
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError(
                "Key must be 16, 24, or 32 UTF-8 bytes (got %d).\n"
                "For AES-128 use a 16-character key (e.g. 'M@{n$vdXnJ)4F!>h')." % len(key_bytes)
            )
        if len(iv_bytes) != 16:
            raise ValueError(
                "IV must be exactly 16 UTF-8 bytes (got %d).\n"
                "Leave blank to reuse the key as IV (matching JS default)." % len(iv_bytes)
            )
        return key_bytes, iv_bytes

    @staticmethod
    def encrypt(plaintext_str, key_utf8, iv_utf8=None):
        """
        Encrypt plaintext_str with AES-128-CBC, PKCS5 padding.
        Returns Base64-encoded ciphertext string.
        Matches: crypto.subtle.encrypt({name:'AES-CBC', iv:v}, K, encoded)
        """
        try:
            key_bytes, iv_bytes = AesCbcEngine._prepare(key_utf8, iv_utf8 or "")
            secret_key = SecretKeySpec(key_bytes, "AES")
            iv_spec    = IvParameterSpec(iv_bytes)
            cipher     = Cipher.getInstance(AesCbcEngine.ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, secret_key, iv_spec)
            plaintext_bytes = plaintext_str.encode("UTF-8")
            encrypted_bytes = cipher.doFinal(plaintext_bytes)
            return base64.b64encode(bytes(bytearray(encrypted_bytes)))
        except Exception as e:
            raise RuntimeError("AES-CBC encrypt failed: %s" % str(e))

    @staticmethod
    def decrypt(ciphertext_b64, key_utf8, iv_utf8=None):
        """
        Decrypt a Base64 ciphertext string with AES-128-CBC, PKCS5 padding.
        Returns the original plaintext string.
        Matches: crypto.subtle.decrypt({name:'AES-CBC', iv:v}, K, cipherBytes)
        """
        try:
            key_bytes, iv_bytes = AesCbcEngine._prepare(key_utf8, iv_utf8 or "")
            secret_key      = SecretKeySpec(key_bytes, "AES")
            iv_spec         = IvParameterSpec(iv_bytes)
            cipher          = Cipher.getInstance(AesCbcEngine.ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, secret_key, iv_spec)
            # Accept both str and bytes for the base64 input
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            decrypted_bytes  = cipher.doFinal(ciphertext_bytes)
            return bytearray(decrypted_bytes).decode("UTF-8")
        except Exception as e:
            raise RuntimeError("AES-CBC decrypt failed: %s" % str(e))



# =============================================================================
# Extensible Crypto Snippet System
# Works exactly like the hash SnippetManager -- users add new algorithms by
# adding entries to crypto_snippets.json with encrypt_code / decrypt_code.
# =============================================================================
class CryptoSnippetManager:
    """
    Manages crypto_snippets.json. Each entry has:
      encrypt_code  : Python code defining encrypt(plaintext, key, iv) -> str
      decrypt_code  : Python code defining decrypt(ciphertext_b64, key, iv) -> str
      requires_key  : bool
      requires_iv   : bool
      description   : str
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.snippets = {}
        self.load_snippets()

    # ------------------------------------------------------------------
    # Built-in algorithm templates (added automatically if missing)
    # ------------------------------------------------------------------
    _BUILTIN_AES128_ENC = (
        "def encrypt(plaintext, key, iv):\n"
        "    kb = key.encode('UTF-8')\n"
        "    ib = iv.encode('UTF-8') if iv else kb[:16]\n"
        "    sk = SecretKeySpec(kb, 'AES')\n"
        "    c  = Cipher.getInstance('AES/CBC/PKCS5Padding')\n"
        "    c.init(1, sk, IvParameterSpec(ib))\n"
        "    return base64.b64encode(bytes(bytearray(c.doFinal(plaintext.encode('UTF-8')))))\n"
    )
    _BUILTIN_AES128_DEC = (
        "def decrypt(ciphertext_b64, key, iv):\n"
        "    kb = key.encode('UTF-8')\n"
        "    ib = iv.encode('UTF-8') if iv else kb[:16]\n"
        "    sk = SecretKeySpec(kb, 'AES')\n"
        "    c  = Cipher.getInstance('AES/CBC/PKCS5Padding')\n"
        "    c.init(2, sk, IvParameterSpec(ib))\n"
        "    return bytearray(c.doFinal(base64.b64decode(ciphertext_b64))).decode('UTF-8')\n"
    )
    _BUILTIN_AES256_ENC = (
        "def encrypt(plaintext, key, iv):\n"
        "    # key = 32-byte UTF-8 string, iv = 16-byte UTF-8 string\n"
        "    kb = key.encode('UTF-8')\n"
        "    ib = iv.encode('UTF-8')\n"
        "    sk = SecretKeySpec(kb, 'AES')\n"
        "    c  = Cipher.getInstance('AES/CBC/PKCS5Padding')\n"
        "    c.init(1, sk, IvParameterSpec(ib))\n"
        "    return base64.b64encode(bytes(bytearray(c.doFinal(plaintext.encode('UTF-8')))))\n"
    )
    _BUILTIN_AES256_DEC = (
        "def decrypt(ciphertext_b64, key, iv):\n"
        "    # key = 32-byte UTF-8 string, iv = 16-byte UTF-8 string\n"
        "    kb = key.encode('UTF-8')\n"
        "    ib = iv.encode('UTF-8')\n"
        "    sk = SecretKeySpec(kb, 'AES')\n"
        "    c  = Cipher.getInstance('AES/CBC/PKCS5Padding')\n"
        "    c.init(2, sk, IvParameterSpec(ib))\n"
        "    return bytearray(c.doFinal(base64.b64decode(ciphertext_b64))).decode('UTF-8')\n"
    )

    def _ensure_builtin_defaults(self):
        """Insert built-in algorithms if they are not already in the snippets file."""
        changed = False
        if "AES-CBC-128" not in self.snippets:
            self.snippets["AES-CBC-128"] = {
                "encrypt_code": self._BUILTIN_AES128_ENC,
                "decrypt_code": self._BUILTIN_AES128_DEC,
                "description":  "AES-128-CBC, PKCS5 padding. Key=16-byte UTF-8; IV=16-byte UTF-8 (blank reuses Key).",
                "requires_key": True,
                "requires_iv":  False,
            }
            changed = True
        if "AES-CBC-256" not in self.snippets:
            self.snippets["AES-CBC-256"] = {
                "encrypt_code": self._BUILTIN_AES256_ENC,
                "decrypt_code": self._BUILTIN_AES256_DEC,
                "description":  "AES-CBC-256, PKCS5/PKCS7 padding. Key=32-byte UTF-8; IV=16-byte UTF-8 (required).",
                "requires_key": True,
                "requires_iv":  True,
            }
            changed = True
        if changed:
            self.save_snippets()

    def load_snippets(self):
        if not os.path.exists(self.filepath):
            self.snippets = {}
            self._ensure_builtin_defaults()
            return
        try:
            with open(self.filepath, 'r') as f:
                self.snippets = json.load(f)
        except Exception as e:
            print("[CipherKit] Error loading crypto snippets: %s" % str(e))
            self.snippets = {}
        self._ensure_builtin_defaults()

    def save_snippets(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.snippets, f, indent=2)
            return True
        except Exception as e:
            print("[CipherKit] Error saving crypto snippets: %s" % str(e))
            return False

    def get_snippet(self, name):
        return self.snippets.get(name)

    def get_all_names(self):
        return list(self.snippets.keys())

    def update_snippet(self, name, encrypt_code, decrypt_code,
                       description="", requires_key=True, requires_iv=True):
        self.snippets[name] = {
            "encrypt_code": encrypt_code,
            "decrypt_code": decrypt_code,
            "description": description,
            "requires_key": requires_key,
            "requires_iv": requires_iv
        }
        self.save_snippets()

    def delete_snippet(self, name):
        if name in self.snippets:
            del self.snippets[name]
            self.save_snippets()

    def requires_key(self, name):
        s = self.snippets.get(name, {})
        return s.get("requires_key", True)

    def requires_iv(self, name):
        s = self.snippets.get(name, {})
        return s.get("requires_iv", True)


class CryptoSnippetEngine:
    """
    Executes encrypt_code or decrypt_code from a crypto snippet.
    Both functions receive (plaintext_or_ciphertext, key, iv) and return a string.
    """

    @staticmethod
    def execute(snippet, mode, input_text, key, iv):
        """
        mode: 'Encrypt' or 'Decrypt'
        Returns result string, or raises RuntimeError on failure.
        """
        local_scope  = {}
        global_scope = {
            "base64": base64,
            "json":   json,
            "time":   time,
            # Expose javax.crypto for snippets that use the JVM directly
            "Cipher":         Cipher,
            "SecretKeySpec":  SecretKeySpec,
            "IvParameterSpec": IvParameterSpec,
        }
        try:
            if mode == "Encrypt":
                code   = snippet.get("encrypt_code", "")
                fn_key = "encrypt"
            else:
                code   = snippet.get("decrypt_code", "")
                fn_key = "decrypt"

            if not code:
                raise ValueError("No %s_code found in crypto snippet." % fn_key)

            exec(code, global_scope, local_scope)

            if fn_key not in local_scope:
                raise ValueError(
                    "Crypto snippet must define a '%s(input, key, iv)' function." % fn_key
                )

            result = local_scope[fn_key](input_text, key, iv)
            return str(result)

        except Exception as e:
            raise RuntimeError("%s failed: %s\n%s" % (
                mode, str(e), traceback.format_exc()
            ))


# =============================================================================
# Preset Manager: save/load per-API configurations
# =============================================================================
class PresetManager:
    """Manages app-level presets stored in a JSON file.
    Each app preset holds shared config + per-endpoint keys_order entries."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.presets = {}
        self.load()

    def load(self):
        if not os.path.exists(self.filepath):
            self.presets = {}
            self.save()
            return
        try:
            with open(self.filepath, 'r') as f:
                data = json.load(f)
            # Migrate old flat format (has "match_pattern" key at app level)
            migrated = {}
            for name, app in data.items():
                if "match_pattern" in app:
                    pattern = app.get("match_pattern", "")
                    h = app.get("hash", {})
                    c = app.get("crypto", {})
                    migrated[name] = {
                        "algorithm":   h.get("algorithm", ""),
                        "secret":      h.get("secret", ""),
                        "custom_data": h.get("custom_data", {}),
                        "hash_field":  h.get("hash_field", "hash"),
                        "crypto":      c,
                        "endpoints":   {pattern: {"keys_order": h.get("keys_order", "")}} if pattern else {},
                    }
                else:
                    migrated[name] = app
            self.presets = migrated
            if migrated != data:
                self.save()
        except Exception as e:
            print("[CipherKit] Error loading presets: %s" % str(e))
            self.presets = {}

    def save(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.presets, f, indent=2)
            return True
        except Exception as e:
            print("[CipherKit] Error saving presets: %s" % str(e))
            return False

    def get_all_names(self):
        return list(self.presets.keys())

    def get_app(self, name):
        return self.presets.get(name)

    def save_app(self, name, data):
        """Save or update app-level config, preserving existing endpoints."""
        if name in self.presets:
            data["endpoints"] = self.presets[name].get("endpoints", {})
        else:
            data.setdefault("endpoints", {})
        self.presets[name] = data
        self.save()

    def save_endpoint(self, app_name, url_pattern, keys_order):
        """Add or update a single endpoint's keys_order under an app."""
        if app_name not in self.presets:
            self.presets[app_name] = {"endpoints": {}}
        self.presets[app_name].setdefault("endpoints", {})
        self.presets[app_name]["endpoints"][url_pattern] = {"keys_order": keys_order}
        self.save()

    def delete_app(self, name):
        if name in self.presets:
            del self.presets[name]
            self.save()

    def find_by_url(self, url_path):
        """Return (app_name, app_data, url_pattern, endpoint_data) for first matching endpoint."""
        for app_name, app in self.presets.items():
            for pattern, ep in app.get("endpoints", {}).items():
                if pattern and pattern in url_path:
                    return (app_name, app, pattern, ep)
        return (None, None, None, None)


# =============================================================================
# UI Helper: Rounded Border for Swing components
# =============================================================================
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
# =============================================================================
class CustomDataPanel(JPanel):
    """
    A panel that holds one or more key:value custom data fields.
    Each row: [key_name] : [value] [+] [-]
    getPairs() returns {key: value} dict used by CryptoEngine.
    """

    def __init__(self, label_font=None, field_font=None):
        JPanel.__init__(self)
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self._label_font = label_font  # None = inherit LaF
        self._field_font = field_font  # None = inherit LaF
        self._rows = []  # list of (key_field, value_field)
        self._addFieldRow()

    def _addFieldRow(self, key="", value=""):
        row = JPanel(BorderLayout(4, 0))
        row.setMaximumSize(Dimension(9999, 30))
        row.setAlignmentX(Component.LEFT_ALIGNMENT)

        # Key field (narrower, fixed ~90px)
        keyField = JTextField(key)
        keyField.setPreferredSize(Dimension(90, 26))
        keyField.setToolTipText("Key name (use in Keys Order)")

        # Separator label
        sep = JLabel(":")
        sep.setBorder(EmptyBorder(0, 4, 0, 4))

        # Value field (stretches)
        valueField = JTextField(value)

        # Left part: key + colon + value
        kvPanel = JPanel(BorderLayout(0, 0))
        kvPanel.add(keyField, BorderLayout.WEST)
        kvPanel.add(sep, BorderLayout.CENTER)
        kvPanel.add(valueField, BorderLayout.EAST)
        # Make value field stretch with remaining space
        kvPanel2 = JPanel(BorderLayout(2, 0))
        kvPanel2.add(keyField, BorderLayout.WEST)
        kvPanel2.add(sep, BorderLayout.CENTER)
        kvPanel2.add(valueField, BorderLayout.CENTER)
        row.add(kvPanel2, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 2, 0))
        addBtn = JButton("+")
        addBtn.setPreferredSize(Dimension(32, 24))
        addBtn.setToolTipText("Add another custom data field")
        addBtn.addActionListener(lambda e: self._onAdd())
        btnPanel.add(addBtn)

        removeBtn = JButton("-")
        removeBtn.setPreferredSize(Dimension(32, 24))
        removeBtn.setToolTipText("Remove this field")
        removeBtn.addActionListener(lambda e, r=row, kf=keyField, vf=valueField: self._onRemove(r, kf, vf))
        btnPanel.add(removeBtn)

        row.add(btnPanel, BorderLayout.EAST)

        self._rows.append((keyField, valueField))
        self.add(row)
        self.add(Box.createVerticalStrut(3))
        self.revalidate()
        self.repaint()

    def _onAdd(self):
        self._addFieldRow()

    def _onRemove(self, row, keyField, valueField):
        if len(self._rows) <= 1:
            keyField.setText("")
            valueField.setText("")
            return
        self._rows.remove((keyField, valueField))
        self.remove(row)
        comps = self.getComponents()
        for c in comps:
            if isinstance(c, Box.Filler):
                self.remove(c)
                break
        self.revalidate()
        self.repaint()

    def getPairs(self):
        """Return dict of {key: value} for all rows with a key name."""
        result = {}
        for kf, vf in self._rows:
            k = kf.getText().strip()
            v = vf.getText()
            if k:
                result[k] = v
        return result

    def getKeys(self):
        """Return list of non-empty key names."""
        return [kf.getText().strip() for kf, vf in self._rows if kf.getText().strip()]

    def getValues(self):
        """Return list of values (backward compat)."""
        return [vf.getText() for kf, vf in self._rows]

    def setPairs(self, pairs):
        """Set rows from a dict {key: value}."""
        self.removeAll()
        self._rows = []
        if not pairs:
            self._addFieldRow()
            return
        for k, v in pairs.items():
            self._addFieldRow(str(k), str(v) if v else "")

    def getFirstValue(self):
        if self._rows:
            return self._rows[0][1].getText()
        return ""


# =============================================================================
# Compact Custom Data Panel for inline editor tab (narrower, key:value)
# =============================================================================
class CompactCustomDataPanel(JPanel):
    """Compact key:value custom data panel for the inline request editor tab."""

    def __init__(self, font=None):
        JPanel.__init__(self)
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self._font = font  # None = inherit default LaF font
        self._rows = []
        self._addFieldRow()

    def _addFieldRow(self, key="", value=""):
        row = JPanel(BorderLayout(2, 0))
        row.setMaximumSize(Dimension(9999, 24))
        row.setAlignmentX(Component.LEFT_ALIGNMENT)

        keyField = JTextField(key)
        keyField.setPreferredSize(Dimension(70, 20))
        keyField.setToolTipText("Key name (use in Keys Order)")

        sep = JLabel(":")
        sep.setBorder(EmptyBorder(0, 2, 0, 2))

        valueField = JTextField(value)

        # key | ":" in a fixed-width panel, value takes the rest
        keyWithSep = JPanel(BorderLayout(0, 0))
        keyWithSep.add(keyField, BorderLayout.CENTER)
        keyWithSep.add(sep, BorderLayout.EAST)
        keyWithSep.setPreferredSize(Dimension(80, 20))

        kvPanel = JPanel(BorderLayout(2, 0))
        kvPanel.add(keyWithSep, BorderLayout.WEST)
        kvPanel.add(valueField, BorderLayout.CENTER)
        row.add(kvPanel, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 1, 0))
        addBtn = JButton("+")
        addBtn.setPreferredSize(Dimension(26, 20))
        addBtn.addActionListener(lambda e: self._onAdd())
        btnPanel.add(addBtn)

        removeBtn = JButton("-")
        removeBtn.setPreferredSize(Dimension(26, 20))
        removeBtn.addActionListener(lambda e, r=row, kf=keyField, vf=valueField: self._onRemove(r, kf, vf))
        btnPanel.add(removeBtn)

        row.add(btnPanel, BorderLayout.EAST)

        self._rows.append((keyField, valueField))
        self.add(row)
        self.add(Box.createVerticalStrut(2))
        self.revalidate()
        self.repaint()

    def _onAdd(self):
        self._addFieldRow()

    def _onRemove(self, row, keyField, valueField):
        if len(self._rows) <= 1:
            keyField.setText("")
            valueField.setText("")
            return
        self._rows.remove((keyField, valueField))
        self.remove(row)
        comps = self.getComponents()
        for c in comps:
            if isinstance(c, Box.Filler):
                self.remove(c)
                break
        self.revalidate()
        self.repaint()

    def getPairs(self):
        result = {}
        for kf, vf in self._rows:
            k = kf.getText().strip()
            v = vf.getText()
            if k:
                result[k] = v
        return result

    def getKeys(self):
        return [kf.getText().strip() for kf, vf in self._rows if kf.getText().strip()]

    def getValues(self):
        return [vf.getText() for kf, vf in self._rows]

    def setPairs(self, pairs):
        self.removeAll()
        self._rows = []
        if not pairs:
            self._addFieldRow()
            return
        for k, v in pairs.items():
            self._addFieldRow(str(k), str(v) if v else "")

    def getFirstValue(self):
        if self._rows:
            return self._rows[0][1].getText()
        return ""


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
    Two sub-tabs (Hash / Crypto) let users switch config view;
    both are always active and work simultaneously.
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers  = extender._helpers
        self._editable = editable
        self._currentMessage = None
        self._headerBytes    = None
        self._contentType    = ""
        self._keysUserEdited = False

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
        hashConfigPanel.add(JLabel("Keys Order:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        self._keysField = JTextField()
        self._keysField.getDocument().addDocumentListener(
            PayloadDocumentListener(self._onKeysManualEdit)
        )
        hashConfigPanel.add(self._keysField, hgbc)

        # Row 4: Hash Field + Buttons
        hgbc.gridy = 4; hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE
        hashConfigPanel.add(JLabel("Hash Field:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        hashRow = JPanel(BorderLayout(4, 0))
        self._hashFieldName = JTextField("hash")
        self._hashFieldName.setToolTipText("JSON key name where the hash will be injected")
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
        self._cryptoRunBtn    = JButton("Run Crypto",   actionPerformed=self._onCryptoRun)
        self._cryptoInjectBtn = JButton("Run & Inject", actionPerformed=self._onCryptoAndInject)
        self._cryptoInjectBtn.setToolTipText(
            "Run crypto on the field value and inject result back into body"
        )
        cryptoBtnPanel.add(self._cryptoRunBtn)
        cryptoBtnPanel.add(self._cryptoInjectBtn)
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

        # Row 1: Additional Values
        kgbc.gridy = 1; kgbc.gridx = 0; kgbc.weightx = 0; kgbc.fill = GridBagConstraints.NONE
        kgbc.anchor = GridBagConstraints.NORTHWEST
        kfPanel.add(JLabel("Additional Values:"), kgbc)
        kgbc.gridx = 1; kgbc.gridwidth = 2; kgbc.weightx = 1.0; kgbc.fill = GridBagConstraints.HORIZONTAL
        kgbc.anchor = GridBagConstraints.WEST
        self._inlineKfAdditionalArea = JTextArea(2, 40)
        self._inlineKfAdditionalArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._inlineKfAdditionalArea.setLineWrap(True)
        self._inlineKfAdditionalArea.setToolTipText("Extra key: value pairs not in body, e.g. API: abc123")
        kfPanel.add(JScrollPane(self._inlineKfAdditionalArea), kgbc)
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

        # Add all sub-tabs
        configTabs.addTab("Hash",       hashConfigPanel)
        configTabs.addTab("Crypto",     cryptoConfigPanel)
        configTabs.addTab("Key Finder", kfPanel)

        # ----------------------------------------------------------------
        # Preset sub-tab panel
        # ----------------------------------------------------------------
        presetTabPanel = JPanel(GridBagLayout())
        presetTabPanel.setBorder(EmptyBorder(6, 6, 6, 6))
        pgbc = GridBagConstraints()
        pgbc.insets = Insets(3, 4, 3, 4)
        pgbc.anchor = GridBagConstraints.WEST

        # Row 0: App selector + Load + Delete
        pgbc.gridy = 0; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        presetTabPanel.add(JLabel("App:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_appRow = JPanel(BorderLayout(4, 0))
        _pt_preset_names = ["(none)"] + extender.preset_manager.get_all_names()
        self._inlinePresetCombo = JComboBox(_pt_preset_names)
        self._inlinePresetCombo.setToolTipText("Select app preset to load (algorithm, secret, crypto settings)")
        self._inlinePresetCombo.addActionListener(lambda e: self._refreshInlinePresetInfo())
        _pt_appRow.add(self._inlinePresetCombo, BorderLayout.CENTER)
        _pt_appBtns = JPanel(FlowLayout(FlowLayout.RIGHT, 3, 0))
        _pt_loadBtn = JButton("Load", actionPerformed=self._onInlineLoadPreset)
        _pt_loadBtn.setToolTipText("Load selected app preset into all config fields")
        _pt_delBtn  = JButton("Delete App", actionPerformed=self._onInlineDeletePreset)
        _pt_delBtn.setToolTipText("Delete this app preset and all its endpoints")
        _pt_appBtns.add(_pt_loadBtn)
        _pt_appBtns.add(_pt_delBtn)
        _pt_appRow.add(_pt_appBtns, BorderLayout.EAST)
        presetTabPanel.add(_pt_appRow, pgbc)

        # Row 1: Current URL (read-only info)
        pgbc.gridy = 1; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        presetTabPanel.add(JLabel("Current URL:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineUrlLabel = JTextField("")
        self._inlineUrlLabel.setEditable(False)
        self._inlineUrlLabel.setForeground(Color(80, 80, 80))
        presetTabPanel.add(self._inlineUrlLabel, pgbc)

        # Row 2: Endpoint keys order (editable, linked to main keys field)
        pgbc.gridy = 2; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        presetTabPanel.add(JLabel("Keys Order:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_epRow = JPanel(BorderLayout(4, 0))
        self._inlineEpKeysField = JTextField("")
        self._inlineEpKeysField.setToolTipText("Keys order for this endpoint (comma-separated)")
        _pt_epRow.add(self._inlineEpKeysField, BorderLayout.CENTER)
        _pt_saveEpBtn = JButton("Save Endpoint", actionPerformed=self._onInlineSavePreset)
        _pt_saveEpBtn.setToolTipText(
            "Save this URL + keys order under the selected app.\n"
            "Do this once per endpoint - it auto-loads next time."
        )
        _pt_epRow.add(_pt_saveEpBtn, BorderLayout.EAST)
        presetTabPanel.add(_pt_epRow, pgbc)

        # Row 3: Status / last auto-load info
        pgbc.gridy = 3; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        presetTabPanel.add(JLabel("Status:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlinePresetStatus = JTextField("No preset loaded")
        self._inlinePresetStatus.setEditable(False)
        self._inlinePresetStatus.setForeground(Color(80, 80, 80))
        presetTabPanel.add(self._inlinePresetStatus, pgbc)

        # Filler row to push content to top
        pgbc.gridy = 4; pgbc.gridx = 0; pgbc.gridwidth = 2
        pgbc.weighty = 1.0; pgbc.fill = GridBagConstraints.VERTICAL
        presetTabPanel.add(JPanel(), pgbc)

        configTabs.addTab("Hash",       hashConfigPanel)
        configTabs.addTab("Crypto",     cryptoConfigPanel)
        configTabs.addTab("Key Finder", kfPanel)
        configTabs.addTab("Preset",     presetTabPanel)

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
        self._bodyArea.addFocusListener(PayloadFocusListener(self._tryFormatJson))
        bodyScroll = JScrollPane(self._bodyArea)
        bodyScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bodyWrap.add(bodyScroll, BorderLayout.CENTER)

        # Fix: give bodyWrap a minimum size so JSplitPane can never collapse it to zero
        bodyWrap.setMinimumSize(Dimension(0, 80))

        outputWrap = JPanel(BorderLayout(0, 2))
        outputWrap.setMinimumSize(Dimension(0, 60))

        # Header row: "Output:" label on left, checkbox on right
        outputHeader = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        outputHeader.add(JLabel("Output: "))
        self._autoEncryptChk = JCheckBox("Auto-encrypt on edit", True)
        self._autoEncryptChk.setToolTipText(
            "When checked: editing the decrypted text automatically re-encrypts it back into the request body"
        )
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

        # ---- Card 3: Preset info - shows saved config for current preset ----
        presetCard = JPanel(BorderLayout(0, 6))
        presetCard.setBorder(EmptyBorder(6, 6, 6, 6))
        self._presetInfoArea = JTextArea()
        self._presetInfoArea.setEditable(False)
        self._presetInfoArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._presetInfoArea.setLineWrap(False)
        self._presetInfoArea.setText("(no preset matched for this request)")
        presetCard.add(JScrollPane(self._presetInfoArea), BorderLayout.CENTER)

        centerPanel.add(hashCryptoCard, "hashcrypto")
        centerPanel.add(kfCard,         "keyfinder")
        centerPanel.add(presetCard,     "preset")
        self._panel.add(centerPanel, BorderLayout.CENTER)

        # Switch cards + auto-decrypt/parse when tabs change
        _outer = self
        from javax.swing.event import ChangeListener as _CL
        class _TabListener(_CL):
            def stateChanged(self, e):
                try:
                    idx = _outer._configTabs.getSelectedIndex()
                    if idx == 2:  # Key Finder
                        _outer._cryptoAutoMode = False
                        _outer._cryptoDebounceTimer.stop()
                        _outer._hashOutput.setEditable(False)
                        _outer._cardLayout.show(centerPanel, "keyfinder")
                        _outer._onInlineKfParse()
                    elif idx == 3:  # Preset tab
                        _outer._cryptoAutoMode = False
                        _outer._cryptoDebounceTimer.stop()
                        _outer._hashOutput.setEditable(False)
                        _outer._cardLayout.show(centerPanel, "preset")
                        _outer._onPresetTabFocus()
                    else:
                        _outer._cardLayout.show(centerPanel, "hashcrypto")
                        if idx == 1:  # Crypto tab
                            _outer._onAutoDecrypt()
                        else:  # Hash tab (idx == 0)
                            _outer._cryptoAutoMode = False
                            _outer._cryptoDebounceTimer.stop()
                            _outer._hashOutput.setEditable(False)
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
                mainCryptoMode = ext._cryptoModeCombo.getSelectedItem()
                if mainCryptoMode:
                    self._inlineCryptoMode.setSelectedItem(mainCryptoMode)
            except Exception as e:
                print("[CipherKit] Sync crypto error: %s" % str(e))
        except Exception as e:
            print("[CipherKit] Sync error: %s" % str(e))

    def _tryLoadPreset(self):
        """Try to auto-load a preset matching the current request URL path.
        Returns True if a preset was loaded, False otherwise."""
        try:
            path = getattr(self, '_requestPath', '')
            if not path:
                return False
            app_name, app, pattern, ep = self._extender.preset_manager.find_by_url(path)
            if not app:
                return False
            # App-level fields
            if app.get("algorithm"):
                self._algoCombo.setSelectedItem(app["algorithm"])
            if "secret" in app:
                self._passcodeField.setText(app["secret"])
            if app.get("custom_data"):
                self._customDataPanel.setPairs(app["custom_data"])
            if "hash_field" in app:
                self._hashFieldName.setText(app["hash_field"])
            # Crypto config - set key/iv/field BEFORE mode to avoid spurious
            # "Key is required" from the mode-change listener firing too early
            c = app.get("crypto", {})
            if c.get("algorithm"):
                self._inlineCryptoAlgo.setSelectedItem(c["algorithm"])
            if "key" in c:
                self._inlineCryptoKey.setText(c["key"])
            if "iv" in c:
                self._inlineCryptoIv.setText(c["iv"])
            if "field" in c:
                self._inlineCryptoField.setText(c["field"])
            if c.get("mode"):
                self._inlineCryptoMode.setSelectedItem(c["mode"])
            # Endpoint-level: keys_order
            if ep and "keys_order" in ep:
                self._keysField.setText(ep["keys_order"])
                self._keysUserEdited = True
            # Update Preset tab UI
            try:
                self._inlinePresetCombo.setSelectedItem(app_name)
                self._inlinePresetStatus.setText("Auto-loaded: %s / %s" % (app_name, pattern))
                self._inlineUrlLabel.setText(getattr(self, '_requestPath', ''))
                if ep:
                    self._inlineEpKeysField.setText(ep.get("keys_order", ""))
            except Exception:
                pass
            print("[CipherKit] Auto-loaded preset: %s / %s" % (app_name, pattern))
            return True
        except Exception as e:
            print("[CipherKit] Preset auto-load error: %s" % str(e))
            return False

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
        """Brute-force key order from inline Key Finder fields."""
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
        # Additional values
        for line in self._inlineKfAdditionalArea.getText().strip().splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                pairs[k.strip()] = v.strip()

        if not pairs:
            self._inlineKfResultArea.setText("No fields found. Click Parse Body first.")
            return
        if len(pairs) > _MAX_KF_FIELDS:
            self._inlineKfResultArea.setText("Too many fields (max 10). Edit Parsed Fields to keep only relevant keys.")
            return

        keys = list(pairs.keys())
        matches = []
        total = 0
        for size in range(1, len(keys) + 1):
            for subset in itertools.combinations(keys, size):
                for perm in itertools.permutations(subset):
                    total += 1
                    if "".join(str(pairs[k]) for k in perm) == known:
                        matches.append(perm)

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
            self._inlineKfResultArea.setText("\n".join(lines))

    # --- IMessageEditorTab interface ---

    def getTabCaption(self):
        return "CipherKit"

    def getUiComponent(self):
        return self._panel

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
        if content is None:
            self._bodyArea.setText("")
            self._currentMessage = None
            self._headerBytes = None
            self._contentType = ""
            return

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

        # Pretty-print JSON only; leave form-data as-is
        try:
            parsed = json.loads(body)
            body = json.dumps(parsed, indent=2)
        except:
            pass

        self._bodyArea.setText(body)
        self._bodyArea.setCaretPosition(0)

        # Extract URL path for preset matching
        self._requestPath = ""
        try:
            request_line = analyzed.getHeaders()[0]  # e.g. "POST /api/user HTTP/1.1"
            parts = request_line.split()
            if len(parts) >= 2:
                self._requestPath = parts[1]
        except:
            pass

        # Try auto-load a preset matching this URL path
        preset_loaded = self._tryLoadPreset()

        # Only auto-extract keys if no preset was loaded and user hasn't manually edited
        if not preset_loaded and not self._keysUserEdited:
            self._tryExtractKeys()

        # Sync remaining config from main tab (only fields not set by preset)
        if not preset_loaded:
            self._syncFromMainTab()

        # If the Crypto tab is already selected, re-run auto-decrypt now that
        # key/iv have been populated (the mode-change listener may have fired
        # before the key was set, producing a spurious "Key is required" error)
        try:
            if self._configTabs.getSelectedIndex() == 1:
                self._onAutoDecrypt()
        except Exception:
            pass

    def getMessage(self):
        if self._currentMessage is None:
            return self._currentMessage

        body_str = self._bodyArea.getText().strip()

        try:
            parsed = json.loads(body_str)
            body_str = json.dumps(parsed)
        except:
            pass

        body_bytes = self._helpers.stringToBytes(body_str)

        analyzed = self._helpers.analyzeRequest(self._currentMessage)
        headers = analyzed.getHeaders()
        return self._helpers.buildHttpMessage(headers, body_bytes)

    def isModified(self):
        if self._currentMessage is None:
            return False
        analyzed = self._helpers.analyzeRequest(self._currentMessage)
        bodyOffset = analyzed.getBodyOffset()
        originalBody = self._helpers.bytesToString(self._currentMessage[bodyOffset:])

        currentBody = self._bodyArea.getText().strip()
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
        result, debug_log = self._computeHash()
        self._hashOutput.setText("[HASH] " + str(result))

    def _onGenerateAndInject(self, event=None):
        result, debug_log = self._computeHash()
        if result and not str(result).startswith("Error"):
            self._hashOutput.setText("[HASH] " + str(result))
            body_str = self._bodyArea.getText().strip()
            try:
                ct = getattr(self, '_contentType', '')
                data = parse_body(body_str, ct)
                field_name = self._hashFieldName.getText().strip() or "hash"
                data[field_name] = str(result)
                serialized = serialize_body(data, body_str, ct)
                self._bodyArea.setText(serialized)
                self._bodyArea.setCaretPosition(0)
            except Exception as e:
                self._hashOutput.setText("Error injecting hash: %s" % str(e))
        else:
            self._hashOutput.setText(str(result))

    def _onInlineSavePreset(self, event=None):
        """Save current config as an app preset + endpoint.
        Reads the app name from the combo and keys order from the Preset tab field."""
        path = getattr(self, '_requestPath', '')

        # App name: use combo selection or ask
        selected_combo = str(self._inlinePresetCombo.getSelectedItem())
        existing = self._extender.preset_manager.get_all_names()

        if selected_combo and selected_combo != "(none)":
            app_name = selected_combo
        else:
            choices = existing + ["[ New app... ]"]
            app_name = JOptionPane.showInputDialog(
                self._panel, "App preset name (select existing or type new):", "Save Endpoint",
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

        # URL pattern: pre-fill from Preset tab URL label or current path
        pattern = JOptionPane.showInputDialog(
            self._panel, "URL pattern for this endpoint (e.g. /api/user):",
            "URL Pattern", JOptionPane.PLAIN_MESSAGE, None, None, path
        )
        pattern = str(pattern).strip() if pattern else ""

        # Keys order: prefer Preset tab field (user may have edited it there)
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
        self._extender.preset_manager.save_app(app_name, app_data)
        if pattern:
            self._extender.preset_manager.save_endpoint(app_name, pattern, keys_order)

        self._refreshInlinePresetCombo()
        self._inlinePresetCombo.setSelectedItem(app_name)
        try:
            self._extender._refreshPresetCombo()
        except:
            pass
        label = "%s%s" % (app_name, (" / " + pattern) if pattern else "")
        try:
            self._inlinePresetStatus.setText("Saved: %s" % label)
        except Exception:
            pass
        self._hashOutput.setText("Saved: %s" % label)
        print("[CipherKit] Preset saved: %s" % label)

    def _onInlineLoadPreset(self, event=None):
        """Manually load the selected app preset into all config fields."""
        name = str(self._inlinePresetCombo.getSelectedItem())
        if name == "(none)":
            return
        app = self._extender.preset_manager.get_app(name)
        if not app:
            return
        try:
            if app.get("algorithm"):
                self._algoCombo.setSelectedItem(app["algorithm"])
            if "secret" in app:
                self._passcodeField.setText(app["secret"])
            if app.get("custom_data"):
                self._customDataPanel.setPairs(app["custom_data"])
            if "hash_field" in app:
                self._hashFieldName.setText(app["hash_field"])
            # Crypto: set key/iv/field before mode to avoid spurious auto-decrypt
            c = app.get("crypto", {})
            if c.get("algorithm"):
                self._inlineCryptoAlgo.setSelectedItem(c["algorithm"])
            if "key" in c:
                self._inlineCryptoKey.setText(c["key"])
            if "iv" in c:
                self._inlineCryptoIv.setText(c["iv"])
            if "field" in c:
                self._inlineCryptoField.setText(c["field"])
            if c.get("mode"):
                self._inlineCryptoMode.setSelectedItem(c["mode"])
            # Try to match current URL path to an endpoint within this app
            path = getattr(self, '_requestPath', '')
            endpoints = app.get("endpoints", {})
            matched_ep = None
            for pat, ep in endpoints.items():
                if pat and pat in path:
                    matched_ep = ep
                    break
            if matched_ep and "keys_order" in matched_ep:
                self._keysField.setText(matched_ep["keys_order"])
                self._keysUserEdited = True
            self._hashOutput.setText("Loaded preset: %s" % name)
            print("[CipherKit] Manually loaded preset: %s" % name)
        except Exception as e:
            print("[CipherKit] Load preset error: %s" % str(e))

    def _refreshInlinePresetCombo(self):
        """Refresh the inline preset combo box with current app names."""
        try:
            current = str(self._inlinePresetCombo.getSelectedItem())
            self._inlinePresetCombo.removeAllItems()
            self._inlinePresetCombo.addItem("(none)")
            for n in self._extender.preset_manager.get_all_names():
                self._inlinePresetCombo.addItem(n)
            if current and current != "(none)":
                self._inlinePresetCombo.setSelectedItem(current)
        except Exception as e:
            print("[CipherKit] Refresh inline combo error: %s" % str(e))

    def _onPresetTabFocus(self):
        """Populate the Preset tab fields and info area when switching to it."""
        try:
            path = getattr(self, '_requestPath', '')
            self._inlineUrlLabel.setText(path or "(no request loaded)")
            self._inlineEpKeysField.setText(self._keysField.getText())
            self._refreshInlinePresetInfo()
        except Exception as e:
            print("[CipherKit] Preset tab focus error: %s" % str(e))

    def _refreshInlinePresetInfo(self):
        """Refresh the preset info text area with the selected app's saved config."""
        try:
            name = str(self._inlinePresetCombo.getSelectedItem())
            if name == "(none)":
                self._presetInfoArea.setText("(no preset selected - pick one from the dropdown above)")
                return
            app = self._extender.preset_manager.get_app(name)
            if not app:
                self._presetInfoArea.setText("(preset '%s' not found)" % name)
                return
            path = getattr(self, '_requestPath', '')
            lines = []
            lines.append("App Preset : %s" % name)
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
            self._presetInfoArea.setText("\n".join(lines))
            self._presetInfoArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] Preset info refresh error: %s" % str(e))

    def _onInlineDeletePreset(self, event=None):
        """Delete the selected app preset."""
        name = str(self._inlinePresetCombo.getSelectedItem())
        if name == "(none)":
            return
        confirm = JOptionPane.showConfirmDialog(
            self._panel, "Delete app preset '%s' and all its endpoints?" % name,
            "Delete Preset", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self._extender.preset_manager.delete_app(name)
            self._refreshInlinePresetCombo()
            try:
                self._extender._refreshPresetCombo()
            except:
                pass
            self._inlinePresetStatus.setText("Deleted: %s" % name)
            print("[CipherKit] Preset deleted: %s" % name)

    def _onCryptoRun(self, event=None):
        """Run AES-CBC encrypt/decrypt on the named body field and show result."""
        try:
            result = self._computeCrypto()
            self._hashOutput.setText("[CRYPTO] " + str(result))
        except Exception as e:
            self._hashOutput.setText("[CRYPTO] Error: %s" % str(e))

    def _onCryptoAndInject(self, event=None):
        """
        Run AES-CBC on the value of the named body field and inject result back.
        - Encrypt mode: reads plaintext from the field, encrypts it, writes Base64 back
        - Decrypt mode: reads Base64 from the field, decrypts it, writes plaintext back
        """
        try:
            result = self._computeCrypto()
            if not result or str(result).startswith("Error"):
                self._hashOutput.setText("[CRYPTO] " + str(result))
                return

            body_str = self._bodyArea.getText().strip()
            ct       = getattr(self, '_contentType', '')
            data     = parse_body(body_str, ct)
            field    = self._inlineCryptoField.getText().strip() or "data"
            data[field] = str(result)
            serialized  = serialize_body(data, body_str, ct)
            self._bodyArea.setText(serialized)
            self._bodyArea.setCaretPosition(0)
            self._hashOutput.setText("[CRYPTO] " + str(result))
        except Exception as e:
            self._hashOutput.setText("[CRYPTO] Error: %s" % str(e))

    def _onAutoDecrypt(self):
        """Auto-decrypt the named field when switching to Crypto tab (Decrypt mode only).
        Silently clears the output and does nothing when required params are missing."""
        self._cryptoAutoMode = False
        self._cryptoDebounceTimer.stop()
        mode = str(self._inlineCryptoMode.getSelectedItem())
        if mode != "Decrypt":
            self._hashOutput.setEditable(False)
            self._hashOutput.setText("")
            return
        # Silently skip if required parameters are not yet filled in
        key   = self._inlineCryptoKey.getText().strip()
        field = self._inlineCryptoField.getText().strip()
        if not key or not field:
            self._hashOutput.setEditable(False)
            self._hashOutput.setText("")
            return
        # IV: only required for algorithms that need one; skip silently if empty
        # (AesCbcEngine accepts None IV and derives one, so we allow empty IV here)
        try:
            result = self._computeCrypto()
            if result and not str(result).startswith("Error"):
                self._hashOutput.setEditable(True)
                self._hashOutput.setText(str(result))
                self._cryptoAutoMode = True
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
        if not self._autoEncryptChk.isSelected():
            return
        # Silently skip if required parameters are missing
        if not self._inlineCryptoKey.getText().strip():
            return
        try:
            plaintext = self._hashOutput.getText()
            if not plaintext:
                return
            key   = self._inlineCryptoKey.getText()
            iv    = self._inlineCryptoIv.getText().strip() or None
            field = self._inlineCryptoField.getText().strip() or "data"
            if not key:
                return
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


# =============================================================================
# Burp Suite Extension Entry Point
# =============================================================================
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CipherKit")

        # Redirect stdout/stderr to Burp's output
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Snippet managers
        ext_file   = callbacks.getExtensionFilename()
        script_dir = os.path.dirname(os.path.abspath(ext_file))
        snippets_path        = os.path.join(script_dir, "snippets.json")
        crypto_snippets_path = os.path.join(script_dir, "crypto_snippets.json")
        presets_path         = os.path.join(script_dir, "presets.json")
        self.snippet_manager        = SnippetManager(snippets_path)
        self.crypto_snippet_manager = CryptoSnippetManager(crypto_snippets_path)
        self.preset_manager         = PresetManager(presets_path)

        # Build main tab UI synchronously
        SwingUtilities.invokeAndWait(self._buildUI)

        # Register all factories
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)

        # Register the main HashGen tab
        callbacks.addSuiteTab(self)

        print("[+] CipherKit extension loaded successfully")
        print("[*] Snippets file:       %s" % snippets_path)
        print("[*] Crypto snippets:     %s" % crypto_snippets_path)
        print("[*] Presets file:         %s" % presets_path)
        print("[*] CipherKit tab added to request editor views")

    # -------------------------------------------------------------------------
    # ITab implementation
    # -------------------------------------------------------------------------
    def getTabCaption(self):
        return "CipherKit"

    def getUiComponent(self):
        return self._mainPanel

    # -------------------------------------------------------------------------
    # IMessageEditorTabFactory implementation
    # -------------------------------------------------------------------------
    def createNewInstance(self, controller, editable):
        try:
            return HashGenEditorTab(self, controller, editable)
        except Exception as e:
            print("[CipherKit] ERROR creating inline tab: %s" % e)
            print(traceback.format_exc())
            return None

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
            item = JMenuItem("Send to CipherKit")
            item.addActionListener(lambda event: self._onContextMenuSend(invocation))
            menu_items.append(item)

        return menu_items if menu_items else None

    def _onContextMenuSend(self, invocation):
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

                    parent = self._mainPanel.getParent()
                    if parent:
                        idx = parent.indexOfComponent(self._mainPanel)
                        if idx >= 0:
                            parent.setSelectedIndex(idx)

                    self._tabbedPane.setSelectedIndex(0)
                    print("[*] Request body sent to CipherKit Hash tab")

    # -------------------------------------------------------------------------
    # Build the Main Tab UI
    # -------------------------------------------------------------------------
    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))


        # Tabbed pane for Generator / Crypto / Editor
        self._tabbedPane = JTabbedPane()
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)

        generatorPanel = self._buildGeneratorTab()
        cryptoPanel        = self._buildCryptoTab()
        editorPanel        = self._buildEditorTab()
        cryptoEditorPanel  = self._buildCryptoEditorTab()
        keyFinderPanel     = self._buildKeyFinderTab()

        presetPanel = self._buildPresetTab()

        self._tabbedPane.addTab("Hash", generatorPanel)
        self._tabbedPane.addTab("Crypto", cryptoPanel)
        self._tabbedPane.addTab("Key Finder", keyFinderPanel)
        self._tabbedPane.addTab("Hash Editor", editorPanel)
        self._tabbedPane.addTab("Crypto Editor", cryptoEditorPanel)
        self._tabbedPane.addTab("Preset", presetPanel)

    # -------------------------------------------------------------------------
    # Generator Tab
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Preset Tab (main CipherKit)
    # -------------------------------------------------------------------------
    def _buildPresetTab(self):
        panel = JPanel(BorderLayout(0, 8))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Top: App selector row
        topRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        topRow.add(JLabel("App Preset:"))
        preset_names = ["(none)"] + self.preset_manager.get_all_names()
        self._presetCombo = JComboBox(preset_names)
        self._presetCombo.setPreferredSize(Dimension(180, 24))
        self._presetCombo.setToolTipText("Select an app preset")
        self._presetCombo.addActionListener(lambda e: self._refreshPresetSummary())
        topRow.add(self._presetCombo)

        _pt_loadBtn = JButton("Load", actionPerformed=self._onPresetSelected)
        _pt_loadBtn.setToolTipText("Load selected preset into Hash / Crypto tabs")
        topRow.add(_pt_loadBtn)

        _pt_saveBtn = JButton("Save New", actionPerformed=self._onSavePreset)
        _pt_saveBtn.setToolTipText("Save current Hash/Crypto config as a new app preset")
        topRow.add(_pt_saveBtn)

        _pt_updateBtn = JButton("Update", actionPerformed=self._onUpdatePreset)
        _pt_updateBtn.setToolTipText("Update the selected preset with current Hash/Crypto config")
        topRow.add(_pt_updateBtn)

        _pt_delBtn = JButton("Delete", actionPerformed=self._onDeletePreset)
        _pt_delBtn.setToolTipText("Delete selected app preset and all its endpoints")
        topRow.add(_pt_delBtn)

        panel.add(topRow, BorderLayout.NORTH)

        # Center: read-only summary of saved config
        self._presetSummaryArea = JTextArea()
        self._presetSummaryArea.setEditable(False)
        self._presetSummaryArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._presetSummaryArea.setLineWrap(False)
        self._presetSummaryArea.setText("(no preset selected)")
        panel.add(JScrollPane(self._presetSummaryArea), BorderLayout.CENTER)

        return panel

    def _buildGeneratorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # --- Left side: inputs ---
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        lgbc = GridBagConstraints()
        lgbc.insets = Insets(3, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.NORTHWEST
        lgbc.gridx = 0
        lgbc.weightx = 1.0
        lgbc.fill = GridBagConstraints.HORIZONTAL

        # Algorithm
        lgbc.gridy = 0
        lgbc.insets = Insets(3, 4, 3, 4)
        lbl = JLabel("Algorithm:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 1
        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        self._algoCombo = JComboBox(names)
        self._algoCombo.addActionListener(lambda e: self._updatePasscodeFieldState())
        leftPanel.add(self._algoCombo, lgbc)

        # Secret
        lgbc.gridy = 2
        lgbc.insets = Insets(10, 4, 3, 4)
        lbl = JLabel("Secret:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 3
        lgbc.insets = Insets(3, 4, 3, 4)
        self._passcodeField = JTextField()
        self._passcodeLabel = lbl
        leftPanel.add(self._passcodeField, lgbc)
        SwingUtilities.invokeLater(lambda: self._updatePasscodeFieldState())

        # Custom Data
        lgbc.gridy = 4
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Custom Data:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 5
        lgbc.insets = Insets(3, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.NORTHWEST
        self._customDataPanel = CustomDataPanel()
        leftPanel.add(self._customDataPanel, lgbc)

        # Keys Order
        lgbc.gridy = 6
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Keys Order (comma separated):")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 7
        lgbc.insets = Insets(3, 4, 3, 4)
        self._keysOrderField = JTextField()
        leftPanel.add(self._keysOrderField, lgbc)

        # Hash Field
        lgbc.gridy = 8
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        leftPanel.add(JLabel("Hash Field:"), lgbc)

        lgbc.gridy = 9
        lgbc.insets = Insets(3, 4, 3, 4)
        self._mainHashFieldName = JTextField("hash")
        self._mainHashFieldName.setToolTipText("JSON key name where the hash will be injected")
        leftPanel.add(self._mainHashFieldName, lgbc)

        # Body Format
        lgbc.gridy = 10
        lgbc.insets = Insets(10, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Body Format:")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 11
        lgbc.insets = Insets(3, 4, 3, 4)
        self._bodyFormatCombo = JComboBox(["JSON", "URL-encoded", "multipart/form-data"])
        leftPanel.add(self._bodyFormatCombo, lgbc)

        # Boundary (only relevant for multipart)
        lgbc.gridy = 12
        lgbc.insets = Insets(6, 4, 3, 4)
        lgbc.anchor = GridBagConstraints.WEST
        lbl = JLabel("Boundary (multipart only):")
        leftPanel.add(lbl, lgbc)

        lgbc.gridy = 13
        lgbc.insets = Insets(3, 4, 3, 4)
        self._boundaryField = JTextField()
        self._boundaryField.setToolTipText("Paste the boundary value from Content-Type header (without leading --)")
        leftPanel.add(self._boundaryField, lgbc)

        # Generate button
        lgbc.gridy = 14
        lgbc.insets = Insets(20, 4, 4, 4)
        lgbc.anchor = GridBagConstraints.NORTHWEST
        self._generateBtn = JButton("Generate", actionPerformed=self._onGenerate)
        leftPanel.add(self._generateBtn, lgbc)

        # Spacer
        lgbc.gridy = 15
        lgbc.weighty = 1.0
        lgbc.insets = Insets(0, 0, 0, 0)
        leftPanel.add(JPanel(), lgbc)


        # -- Right side: text areas with label above each box --
        rightPanel = JPanel(GridBagLayout())
        rightPanel.setBorder(EmptyBorder(0, 0, 0, 0))
        gbc = GridBagConstraints()
        gbc.gridx   = 0
        gbc.weightx = 1.0
        gbc.fill    = GridBagConstraints.HORIZONTAL
        gbc.insets  = Insets(0, 0, 2, 0)

        # Payload label
        gbc.gridy  = 0; gbc.weighty = 0
        rightPanel.add(JLabel("Payload:"), gbc)

        # Payload text area
        gbc.gridy  = 1; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 8, 0)
        self._payloadArea = JTextArea(12, 40)
        self._payloadArea.setFont(Font("Monospaced", Font.PLAIN, 12))
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
        payloadScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(payloadScroll, gbc)

        # Result Hash label
        gbc.gridy  = 2; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Result Hash:"), gbc)

        # Result Hash text area
        gbc.gridy  = 3; gbc.weighty = 0.2; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 8, 0)
        self._outputArea = JTextArea(3, 40)
        self._outputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._outputArea.setLineWrap(True)
        self._outputArea.setWrapStyleWord(True)
        self._outputArea.setEditable(False)
        outputScroll = JScrollPane(self._outputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(outputScroll, gbc)

        # Debug Output label
        gbc.gridy  = 4; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Debug Output:"), gbc)

        # Debug text area
        gbc.gridy  = 5; gbc.weighty = 0.6; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 0, 0)
        self._debugArea = JTextArea(6, 40)
        self._debugArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._debugArea.setForeground(Color(40, 40, 40))
        self._debugArea.setLineWrap(True)
        self._debugArea.setWrapStyleWord(True)
        self._debugArea.setEditable(False)
        debugScroll = JScrollPane(self._debugArea)
        debugScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(debugScroll, gbc)

        # Combine left + right
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(320)
        splitPane.setResizeWeight(0.0)
        panel.add(splitPane, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # Crypto Tab (AES-CBC-128 Encrypt / Decrypt)
    # -------------------------------------------------------------------------
    def _buildCryptoTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        monoFont  = Font("Monospaced", Font.PLAIN, 12)

        # ---- Left config panel ----
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        cgbc = GridBagConstraints()
        cgbc.insets  = Insets(4, 4, 4, 4)
        cgbc.anchor  = GridBagConstraints.NORTHWEST
        cgbc.gridx   = 0
        cgbc.weightx = 1.0
        cgbc.fill    = GridBagConstraints.HORIZONTAL

        # Mode
        cgbc.gridy = 0
        lbl = JLabel("Mode:")
        leftPanel.add(lbl, cgbc)

        cgbc.gridy = 1
        self._cryptoModeCombo = JComboBox(["Encrypt", "Decrypt"])
        leftPanel.add(self._cryptoModeCombo, cgbc)

        # Algorithm (AES-CBC-128 only for now)
        cgbc.gridy = 2
        cgbc.insets = Insets(10, 4, 4, 4)
        lbl = JLabel("Algorithm:")
        leftPanel.add(lbl, cgbc)

        cgbc.gridy = 3
        cgbc.insets = Insets(4, 4, 4, 4)
        crypto_names = self.crypto_snippet_manager.get_all_names()
        if not crypto_names:
            crypto_names = ["(no algorithms -- add via Crypto Editor)"]
        self._cryptoAlgoCombo = JComboBox(crypto_names)
        # Update Key/IV fields when algorithm changes
        self._cryptoAlgoCombo.addActionListener(lambda e: self._updateCryptoFieldState())
        leftPanel.add(self._cryptoAlgoCombo, cgbc)

        # Key
        cgbc.gridy = 4
        cgbc.insets = Insets(10, 4, 4, 4)
        leftPanel.add(JLabel("Key:"), cgbc)

        cgbc.gridy = 5
        cgbc.insets = Insets(4, 4, 4, 4)
        self._cryptoKeyField = JTextField()
        leftPanel.add(self._cryptoKeyField, cgbc)

        # IV
        cgbc.gridy = 6
        cgbc.insets = Insets(10, 4, 4, 4)
        leftPanel.add(JLabel("IV:"), cgbc)

        cgbc.gridy = 7
        cgbc.insets = Insets(4, 4, 4, 4)
        self._cryptoIvField = JTextField()
        leftPanel.add(self._cryptoIvField, cgbc)

        # Field
        cgbc.gridy = 8
        cgbc.insets = Insets(10, 4, 4, 4)
        leftPanel.add(JLabel("Field:"), cgbc)

        cgbc.gridy = 9
        cgbc.insets = Insets(4, 4, 4, 4)
        self._mainCryptoField = JTextField("data")
        self._mainCryptoField.setToolTipText("JSON key to read input from / write output to")
        leftPanel.add(self._mainCryptoField, cgbc)

        # Run button
        cgbc.gridy = 10
        cgbc.insets = Insets(20, 4, 4, 4)
        self._cryptoRunBtn = JButton("Run", actionPerformed=self._onCryptoRun)
        leftPanel.add(self._cryptoRunBtn, cgbc)

        # Spacer
        cgbc.gridy = 11
        cgbc.weighty = 1.0
        cgbc.insets  = Insets(0, 0, 0, 0)
        leftPanel.add(JPanel(), cgbc)

        # ---- Right: input + output text areas ----
        rightPanel = JPanel(GridBagLayout())
        rgbc = GridBagConstraints()
        rgbc.fill    = GridBagConstraints.BOTH
        rgbc.insets  = Insets(2, 0, 2, 0)
        rgbc.gridx   = 0
        rgbc.weightx = 1.0

        # Input label
        rgbc.gridy  = 0
        rgbc.weighty = 0
        rgbc.fill   = GridBagConstraints.HORIZONTAL
        inputLbl    = JLabel("Input (plaintext for Encrypt, Base64 for Decrypt):")
        rightPanel.add(inputLbl, rgbc)

        # Input text area
        rgbc.gridy  = 1
        rgbc.weighty = 1.0
        rgbc.fill   = GridBagConstraints.BOTH
        self._cryptoInputArea = JTextArea(10, 40)
        self._cryptoInputArea.setLineWrap(True)
        self._cryptoInputArea.setWrapStyleWord(True)
        inputScroll = JScrollPane(self._cryptoInputArea)
        inputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(inputScroll, rgbc)

        # Output label
        rgbc.gridy  = 2
        rgbc.weighty = 0
        rgbc.fill   = GridBagConstraints.HORIZONTAL
        outputLbl   = JLabel("Output:")
        rightPanel.add(outputLbl, rgbc)

        # Output text area
        rgbc.gridy  = 3
        rgbc.weighty = 0.4
        rgbc.fill   = GridBagConstraints.BOTH
        self._cryptoOutputArea = JTextArea(4, 40)
        self._cryptoOutputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoOutputArea.setEditable(False)
        self._cryptoOutputArea.setLineWrap(True)
        self._cryptoOutputArea.setWrapStyleWord(True)
        outputScroll = JScrollPane(self._cryptoOutputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(outputScroll, rgbc)

        # Combine left + right
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(320)
        splitPane.setResizeWeight(0.0)
        panel.add(splitPane, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # UI State Helpers: requires_key / requires_iv field visibility
    # -------------------------------------------------------------------------
    def _updatePasscodeFieldState(self):
        """Dim/enable the Secret field in the Hash tab based on requires_key flag."""
        try:
            name    = str(self._algoCombo.getSelectedItem())
            snippet = self.snippet_manager.get_snippet(name)
            needs   = True  # default: key required
            if snippet:
                needs = snippet.get("requires_key", True)
            gray = Color(160, 160, 160)
            black = Color(0, 0, 0)
            if needs:
                self._passcodeField.setEditable(True)
                self._passcodeField.setForeground(black)
                self._passcodeField.setToolTipText(None)
                self._passcodeLabel.setForeground(black)
            else:
                self._passcodeField.setEditable(False)
                self._passcodeField.setForeground(gray)
                self._passcodeField.setToolTipText("Not used for " + name)
                self._passcodeField.setText("")
                self._passcodeLabel.setForeground(gray)
        except Exception:
            pass

    def _updateCryptoFieldState(self):
        """Show/dim Key and IV fields based on the selected crypto algo's flags."""
        try:
            name     = str(self._cryptoAlgoCombo.getSelectedItem())
            needs_k  = self.crypto_snippet_manager.requires_key(name)
            needs_iv = self.crypto_snippet_manager.requires_iv(name)
            gray  = Color(160, 160, 160)
            black = Color(0, 0, 0)
            self._cryptoKeyField.setEditable(needs_k)
            self._cryptoKeyField.setForeground(black if needs_k else gray)
            self._cryptoKeyField.setToolTipText(
                None if needs_k else "Key not required for " + name
            )
            self._cryptoIvField.setEditable(needs_iv)
            self._cryptoIvField.setForeground(black if needs_iv else gray)
            self._cryptoIvField.setToolTipText(
                None if needs_iv else "IV not required for " + name
            )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Preset Actions
    # -------------------------------------------------------------------------
    def _onPresetSelected(self):
        """Load selected app preset into Hash + Crypto main tab fields."""
        try:
            name = str(self._presetCombo.getSelectedItem())
            if name == "(none)":
                return
            app = self.preset_manager.get_app(name)
            if not app:
                return
            if app.get("algorithm"):
                self._algoCombo.setSelectedItem(app["algorithm"])
            if "secret" in app:
                self._passcodeField.setText(app["secret"])
            if app.get("custom_data"):
                self._customDataPanel.setPairs(app["custom_data"])
            if "hash_field" in app:
                self._mainHashFieldName.setText(app["hash_field"])
            # keys_order: show first endpoint's value if available
            endpoints = app.get("endpoints", {})
            if endpoints:
                first_ep = list(endpoints.values())[0]
                self._keysOrderField.setText(first_ep.get("keys_order", ""))
            # Crypto config
            c = app.get("crypto", {})
            if c.get("mode"):
                self._cryptoModeCombo.setSelectedItem(c["mode"])
            if c.get("algorithm"):
                self._cryptoAlgoCombo.setSelectedItem(c["algorithm"])
            if "key" in c:
                self._cryptoKeyField.setText(c["key"])
            if "iv" in c:
                self._cryptoIvField.setText(c["iv"])
            if "field" in c:
                self._mainCryptoField.setText(c["field"])
        except Exception as e:
            print("[CipherKit] Preset load error: %s" % str(e))

    def _onSavePreset(self, event=None):
        """Save current config as an app-level preset."""
        name = JOptionPane.showInputDialog(
            self._mainPanel, "App preset name:", "Save Preset",
            JOptionPane.PLAIN_MESSAGE, None, None, ""
        )
        if not name or not str(name).strip():
            return
        name = str(name).strip()
        app_data = {
            "algorithm":   str(self._algoCombo.getSelectedItem()),
            "secret":      self._passcodeField.getText(),
            "custom_data": self._customDataPanel.getPairs(),
            "hash_field":  self._mainHashFieldName.getText().strip() or "hash",
            "crypto": {
                "mode":      str(self._cryptoModeCombo.getSelectedItem()),
                "algorithm": str(self._cryptoAlgoCombo.getSelectedItem()),
                "key":       self._cryptoKeyField.getText(),
                "iv":        self._cryptoIvField.getText(),
                "field":     self._mainCryptoField.getText().strip() or "data",
            },
        }
        self.preset_manager.save_app(name, app_data)
        self._refreshPresetCombo()
        self._presetCombo.setSelectedItem(name)
        self._refreshPresetSummary()
        print("[CipherKit] Preset saved: %s" % name)

    def _onDeletePreset(self, event=None):
        """Delete the selected app preset."""
        name = str(self._presetCombo.getSelectedItem())
        if name == "(none)":
            return
        confirm = JOptionPane.showConfirmDialog(
            self._mainPanel, "Delete preset '%s'?" % name,
            "Delete Preset", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.preset_manager.delete_app(name)
            self._refreshPresetCombo()
            self._refreshPresetSummary()
            print("[CipherKit] Preset deleted: %s" % name)

    def _onUpdatePreset(self, event=None):
        """Update the currently selected app preset with current Hash/Crypto config (no name prompt)."""
        name = str(self._presetCombo.getSelectedItem())
        if name == "(none)":
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select an app preset first.", "Update Preset",
                JOptionPane.INFORMATION_MESSAGE)
            return
        app_data = {
            "algorithm":   str(self._algoCombo.getSelectedItem()),
            "secret":      self._passcodeField.getText(),
            "custom_data": self._customDataPanel.getPairs(),
            "hash_field":  self._mainHashFieldName.getText().strip() or "hash",
            "crypto": {
                "mode":      str(self._cryptoModeCombo.getSelectedItem()),
                "algorithm": str(self._cryptoAlgoCombo.getSelectedItem()),
                "key":       self._cryptoKeyField.getText(),
                "iv":        self._cryptoIvField.getText(),
                "field":     self._mainCryptoField.getText().strip() or "data",
            },
        }
        self.preset_manager.save_app(name, app_data)
        self._refreshPresetSummary()
        print("[CipherKit] Preset updated: %s" % name)

    def _refreshPresetCombo(self):
        """Refresh the preset combo box with current preset names."""
        current = str(self._presetCombo.getSelectedItem())
        self._presetCombo.removeAllItems()
        self._presetCombo.addItem("(none)")
        for n in self.preset_manager.get_all_names():
            self._presetCombo.addItem(n)
        if current and current != "(none)":
            self._presetCombo.setSelectedItem(current)

    def _refreshPresetSummary(self):
        """Refresh the Preset tab summary text area with the selected app's config."""
        try:
            name = str(self._presetCombo.getSelectedItem())
            if name == "(none)":
                self._presetSummaryArea.setText("(no preset selected)")
                return
            app = self.preset_manager.get_app(name)
            if not app:
                self._presetSummaryArea.setText("(preset not found)")
                return
            lines = []
            lines.append("App Preset : %s" % name)
            lines.append("")
            lines.append("Shared Config")
            lines.append("-" * 44)
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
                lines.append("-" * 44)
                for pat, ep in endpoints.items():
                    lines.append("  %-30s  %s" % (pat, ep.get("keys_order", "")))
            else:
                lines.append("")
                lines.append("No endpoints saved yet.")
            self._presetSummaryArea.setText("\n".join(lines))
            self._presetSummaryArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] Preset summary error: %s" % str(e))

    # -------------------------------------------------------------------------
    # Crypto Editor Tab (add/edit/delete crypto snippet algorithms)
    # -------------------------------------------------------------------------
    def _buildCryptoEditorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Top bar: name + buttons
        topPanel = JPanel(BorderLayout(8, 0))
        topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        self._cryptoSnippetNameField = JTextField()
        self._cryptoSnippetNameField.setBorder(
            _roundedCompound(radius=8, padding=6)
        )
        self._cryptoSnippetNameField.setToolTipText("Algorithm name (e.g. AES-CBC-128, ChaCha20)")
        topPanel.add(self._cryptoSnippetNameField, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        loadBtn   = JButton("Load",   actionPerformed=self._onLoadCryptoSnippet)
        saveBtn   = JButton("Save",   actionPerformed=self._onSaveCryptoSnippet)
        deleteBtn = JButton("Delete", actionPerformed=self._onDeleteCryptoSnippet)
        btnPanel.add(loadBtn)
        btnPanel.add(saveBtn)
        btnPanel.add(deleteBtn)
        topPanel.add(btnPanel, BorderLayout.EAST)
        panel.add(topPanel, BorderLayout.NORTH)

        # Info label
        infoLabel = JLabel(
            "Define encrypt(plaintext, key, iv) and decrypt(ciphertext_b64, key, iv) -- "
            "both must return a string. Use javax.crypto, base64, json as needed."
        )
        infoLabel.setForeground(Color(130, 130, 130))

        # Encrypt code area
        encTemplate = (
            "def encrypt(plaintext, key, iv):\n"
            "    # plaintext : str, key : str, iv : str (may be empty)\n"
            "    # Must return a string (e.g. Base64 ciphertext)\n"
            "    from javax.crypto import Cipher\n"
            "    from javax.crypto.spec import SecretKeySpec, IvParameterSpec\n"
            "    import base64\n"
            "    return \"result\""
        )
        self._cryptoEncArea = JTextArea(10, 60)
        self._cryptoEncArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoEncArea.setTabSize(4)
        self._cryptoEncArea.setText(encTemplate)
        encScroll = JScrollPane(self._cryptoEncArea)
        encScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

        # Decrypt code area
        decTemplate = (
            "def decrypt(ciphertext_b64, key, iv):\n"
            "    # ciphertext_b64 : str (Base64), key : str, iv : str (may be empty)\n"
            "    # Must return a string (plaintext)\n"
            "    from javax.crypto import Cipher\n"
            "    from javax.crypto.spec import SecretKeySpec, IvParameterSpec\n"
            "    import base64\n"
            "    return \"result\""
        )
        self._cryptoDecArea = JTextArea(10, 60)
        self._cryptoDecArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoDecArea.setTabSize(4)
        self._cryptoDecArea.setText(decTemplate)
        decScroll = JScrollPane(self._cryptoDecArea)
        decScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

        codePane = JSplitPane(JSplitPane.VERTICAL_SPLIT, encScroll, decScroll)
        codePane.setResizeWeight(0.5)

        centerPanel = JPanel(BorderLayout(0, 6))
        centerPanel.add(infoLabel, BorderLayout.NORTH)
        centerPanel.add(codePane, BorderLayout.CENTER)
        panel.add(centerPanel, BorderLayout.CENTER)
        return panel

    # -------------------------------------------------------------------------
    # Snippet Editor Tab
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Key Order Finder Tab
    # -------------------------------------------------------------------------
    def _buildKeyFinderTab(self):
        """
        Reverse-engineer key concatenation order.
        Given a JSON / form-data body and a known concatenated string,
        find which permutation of the field values produces that string.

        Layout:
          LEFT  - Body Format, Request Body (large), Additional Values, Parse Body button
          RIGHT - Parsed Fields, Known String, Find Key Order, Results
        """
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # ---- LEFT: Body Format, Request Body, Additional Values, Parse button ----
        leftPanel = JPanel(GridBagLayout())
        leftPanel.setBorder(_roundedCompound(radius=8, padding=10))

        lgbc = GridBagConstraints()
        lgbc.gridx = 0; lgbc.weightx = 1.0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(4, 4, 4, 4)

        # Body format dropdown
        lgbc.gridy = 0; lgbc.weighty = 0
        fmtRow = JPanel(BorderLayout(0, 2))
        fmtRow.add(JLabel("Body Format:"), BorderLayout.NORTH)
        self._kfFormatCombo = JComboBox(["JSON", "Form Data"])
        fmtRow.add(self._kfFormatCombo, BorderLayout.CENTER)
        leftPanel.add(fmtRow, lgbc)

        # Request body textarea (large)
        lgbc.gridy = 1; lgbc.insets = Insets(8, 4, 2, 4)
        leftPanel.add(JLabel("Request Body (paste here):"), lgbc)

        lgbc.gridy = 2; lgbc.weighty = 1.0; lgbc.fill = GridBagConstraints.BOTH
        lgbc.insets = Insets(2, 4, 8, 4)
        self._kfBodyArea = JTextArea(12, 30)
        self._kfBodyArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfBodyArea.setLineWrap(True)
        self._kfBodyArea.setWrapStyleWord(True)
        bodyScroll = JScrollPane(self._kfBodyArea)
        bodyScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        leftPanel.add(bodyScroll, lgbc)

        # Additional values
        lgbc.gridy = 3; lgbc.weighty = 0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(0, 4, 2, 4)
        leftPanel.add(JLabel("Additional Values (key: value):"), lgbc)

        lgbc.gridy = 4; lgbc.weighty = 0.3; lgbc.fill = GridBagConstraints.BOTH
        lgbc.insets = Insets(2, 4, 8, 4)
        self._kfAdditionalArea = JTextArea(3, 26)
        self._kfAdditionalArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfAdditionalArea.setEditable(True)
        self._kfAdditionalArea.setLineWrap(True)
        self._kfAdditionalArea.setToolTipText("Extra keys not in the request body, e.g.  API: A2345@#$...")
        addScroll = JScrollPane(self._kfAdditionalArea)
        addScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        leftPanel.add(addScroll, lgbc)

        # Parse button
        lgbc.gridy = 5; lgbc.weighty = 0; lgbc.fill = GridBagConstraints.HORIZONTAL
        lgbc.insets = Insets(0, 4, 4, 4)
        parseBtn = JButton("Parse Body", actionPerformed=self._onParseKeyFinderBody)
        parseBtn.setToolTipText("Parse the request body and populate Parsed Fields on the right")
        leftPanel.add(parseBtn, lgbc)

        # ---- RIGHT: Parsed Fields, Known String, Find, Results ----
        rightPanel = JPanel(GridBagLayout())
        rgbc = GridBagConstraints()
        rgbc.gridx = 0; rgbc.weightx = 1.0; rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.insets = Insets(0, 0, 2, 0)

        # Parsed fields (editable)
        rgbc.gridy = 0; rgbc.weighty = 0
        rightPanel.add(JLabel("Parsed Fields (key: value):"), rgbc)

        rgbc.gridy = 1; rgbc.weighty = 0.4; rgbc.fill = GridBagConstraints.BOTH
        rgbc.insets = Insets(2, 0, 8, 0)
        self._kfParsedArea = JTextArea(8, 28)
        self._kfParsedArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfParsedArea.setEditable(True)
        self._kfParsedArea.setLineWrap(True)
        self._kfParsedArea.setToolTipText("Auto-filled by Parse Body, or edit manually")
        parsedScroll = JScrollPane(self._kfParsedArea)
        parsedScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(parsedScroll, rgbc)

        # Known concatenated string (bigger box)
        rgbc.gridy = 2; rgbc.weighty = 0; rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Known Concatenated String (the hash input):"), rgbc)

        rgbc.gridy = 3; rgbc.weighty = 0.2; rgbc.fill = GridBagConstraints.BOTH
        rgbc.insets = Insets(2, 0, 8, 0)
        self._kfKnownArea = JTextArea(5, 28)
        self._kfKnownArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfKnownArea.setLineWrap(True)
        self._kfKnownArea.setWrapStyleWord(True)
        knownScroll = JScrollPane(self._kfKnownArea)
        knownScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(knownScroll, rgbc)

        # Find button
        rgbc.gridy = 4; rgbc.weighty = 0; rgbc.fill = GridBagConstraints.HORIZONTAL
        rgbc.insets = Insets(0, 0, 8, 0)
        findBtn = JButton("Find Key Order", actionPerformed=self._onFindOrder)
        rightPanel.add(findBtn, rgbc)

        # Results
        rgbc.gridy = 5; rgbc.insets = Insets(0, 0, 2, 0)
        rightPanel.add(JLabel("Results:"), rgbc)

        rgbc.gridy = 6; rgbc.weighty = 0.4; rgbc.fill = GridBagConstraints.BOTH
        rgbc.insets = Insets(2, 0, 0, 0)
        self._kfResultArea = JTextArea(8, 40)
        self._kfResultArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfResultArea.setEditable(False)
        self._kfResultArea.setLineWrap(True)
        self._kfResultArea.setWrapStyleWord(True)
        resultScroll = JScrollPane(self._kfResultArea)
        resultScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        rightPanel.add(resultScroll, rgbc)

        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel)
        splitPane.setDividerLocation(420)
        splitPane.setResizeWeight(0.45)
        panel.add(splitPane, BorderLayout.CENTER)
        return panel

    def _onParseKeyFinderBody(self, event=None):
        """Parse the body textarea and populate the Parsed Fields textarea."""
        body = self._kfBodyArea.getText().strip()
        fmt  = str(self._kfFormatCombo.getSelectedItem())
        try:
            pairs = self._kfParseBody(body, fmt)
            if not pairs:
                self._kfParsedArea.setText("(no fields found)")
                return
            lines = ["%s: %s" % (k, v) for k, v in pairs.items()]
            self._kfParsedArea.setText("\n".join(lines))
        except Exception as e:
            self._kfParsedArea.setText("Parse error: %s" % str(e))

    def _kfParseBody(self, body, fmt):
        """Return OrderedDict-like list of (key, value) from JSON or form data."""
        from collections import OrderedDict
        pairs = OrderedDict()
        if fmt == "JSON":
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("JSON is not an object")
            for k, v in data.items():
                pairs[str(k)] = str(v)
        else:  # Form Data
            for part in body.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    pairs[k.strip()] = v.strip()
        return pairs

    def _kfReadParsedFields(self):
        """Read the manually-editable Parsed Fields and Additional Values areas back into an OrderedDict."""
        from collections import OrderedDict
        pairs = OrderedDict()
        
        # Read from Parsed Fields
        text1 = self._kfParsedArea.getText().strip()
        for line in text1.splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                pairs[k.strip()] = v.strip()
                
        # Read from Additional Values
        text2 = self._kfAdditionalArea.getText().strip()
        for line in text2.splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                pairs[k.strip()] = v.strip()
                
        return pairs

    def _onFindOrder(self, event=None):
        """
        Brute-force all subsets + permutations to find which key order matches
        the known concatenated string.  Tries every combination of 1..N keys so
        the known string can contain only a subset of the parsed fields.
        """
        known = str(self._kfKnownArea.getText().strip())
        sep   = ""

        if not known:
            self._kfResultArea.setText("Please enter the known concatenated string.")
            return

        pairs = self._kfReadParsedFields()
        if not pairs:
            self._kfResultArea.setText("No fields found. Paste a body and click Parse Body first.")
            return

        if len(pairs) > _MAX_KF_FIELDS:
            self._kfResultArea.setText(
                "Warning: %d fields is too many to brute-force.\n"
                "Use the 'Include Only Keys' filter to narrow it down (max 10)." % len(pairs)
            )
            return

        keys   = list(pairs.keys())
        values = pairs
        matches = []   # list of tuples (subset_size, perm_tuple)
        total   = 0

        # Try every non-empty subset size, then every permutation of that subset
        for size in range(1, len(keys) + 1):
            for subset in itertools.combinations(keys, size):
                for perm in itertools.permutations(subset):
                    total += 1
                    concat = sep.join(str(values[k]) for k in perm)
                    if concat == known:
                        matches.append(perm)

        lines = []
        lines.append("Known string : '%s'" % known)
        lines.append("Fields tried : %s" % ", ".join(keys))
        lines.append("Permutations : %d (all subsets)" % total)
        lines.append("-" * 50)

        if not matches:
            lines.append("No match found.")
            lines.append("")
            lines.append("Tip: check if the separator or values are correct.")
            lines.append("Values used:")
            for k, v in values.items():
                lines.append("  %s = '%s'" % (k, str(v)))
        else:
            lines.append("%d match(es) found:" % len(matches))
            lines.append("")
            for i, perm in enumerate(matches, 1):
                key_order   = ", ".join(perm)
                concat_show = sep.join(str(values[k]) for k in perm)
                lines.append("Match #%d:" % i)
                lines.append("  Key order  : %s" % key_order)
                lines.append("  Concat     : '%s'" % concat_show)
                lines.append("")
            lines.append("Copy the key order above into the Hash tab's 'Keys Order' field.")

        self._kfResultArea.setText("\n".join(lines))


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
        self._snippetNameField.setBorder(
            _roundedCompound(radius=8, padding=6)
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
        infoLabel = JLabel("Python code must define: generate(payload, passcode, custom_data=None, key_order=None)")
        infoLabel.setForeground(Color(130, 130, 130))

        # Code editor area
        self._codeArea = JTextArea(20, 60)
        self._codeArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._codeArea.setTabSize(4)
        self._codeArea.setLineWrap(False)

        default_template = (
            'def generate(payload, passcode, custom_data=None, key_order=None):\n'
            '    import hashlib\n'
            '    # payload = merged dict of Custom Data fields + request body JSON\n'
            '    # custom_data = dict {key_name: value} from Custom Data fields\n'
            '    # key_order = list of key names to sign (from Keys Order field)\n'
            '    \n'
            '    debug_log = "--- Debug Info ---\\n"\n'
            '    debug_log += "Keys received: " + str(list(payload.keys())) + "\\n"\n'
            '    \n'
            '    # You can return just the hash string, OR a tuple (hash, debug_output)\n'
            '    return "hash_result", debug_log'
        )
        self._codeArea.setText(default_template)

        codeScroll = JScrollPane(self._codeArea)
        codeScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

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
        label.setAlignmentX(Component.LEFT_ALIGNMENT)
        return label

    # -------------------------------------------------------------------------
    # Actions: Crypto
    # -------------------------------------------------------------------------
    def _onCryptoRun(self, event=None):
        """Encrypt or decrypt using the selected crypto snippet algorithm."""
        try:
            algo      = str(self._cryptoAlgoCombo.getSelectedItem())
            mode      = str(self._cryptoModeCombo.getSelectedItem())
            key       = self._cryptoKeyField.getText()
            iv        = self._cryptoIvField.getText().strip()
            input_txt = self._cryptoInputArea.getText().strip()

            snippet = self.crypto_snippet_manager.get_snippet(algo)
            if not snippet:
                self._cryptoOutputArea.setText("Error: Algorithm '%s' not found." % algo)
                return

            needs_key = self.crypto_snippet_manager.requires_key(algo)
            if needs_key and not key:
                self._cryptoOutputArea.setText("Error: Key is required for %s." % algo)
                return
            if not input_txt:
                self._cryptoOutputArea.setText("Error: Input is empty.")
                return

            result = CryptoSnippetEngine.execute(snippet, mode, input_txt, key, iv)
            self._cryptoOutputArea.setText(str(result))

        except Exception as e:
            self._cryptoOutputArea.setText("Error: %s" % str(e))

    # -------------------------------------------------------------------------
    # Actions: Generator
    # -------------------------------------------------------------------------
    def _onGenerate(self, event=None):
        name = self._algoCombo.getSelectedItem()
        if not name:
            self._outputArea.setText("Error: No algorithm selected.")
            self._debugArea.setText("")
            return

        snippet = self.snippet_manager.get_snippet(str(name))
        if not snippet:
            self._outputArea.setText("Error: Snippet '%s' not found." % name)
            self._debugArea.setText("")
            return

        try:
            payload_str = self._payloadArea.getText().strip()

            # Build content_type from user-selected format + boundary
            fmt = str(self._bodyFormatCombo.getSelectedItem())
            if fmt == "multipart/form-data":
                boundary = self._boundaryField.getText().strip()
                if boundary:
                    content_type = "multipart/form-data; boundary=" + boundary
                else:
                    content_type = "multipart/form-data"
            elif fmt == "URL-encoded":
                content_type = "application/x-www-form-urlencoded"
            else:
                content_type = "application/json"

            payload = parse_body(payload_str, content_type)
            if not payload:
                self._outputArea.setText("Error: Payload could not be parsed or is empty.")
                self._debugArea.setText("")
                return
            passcode = self._passcodeField.getText()
            custom_data = self._customDataPanel.getPairs()

            keys_str = self._keysOrderField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            result, debug_log = CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, custom_data, key_order
            )

            self._outputArea.setText(str(result))
            self._debugArea.setText(str(debug_log))

        except Exception as e:
            self._outputArea.setText("Error: %s" % str(e))
            self._debugArea.setText(traceback.format_exc())

    def _tryExtractKeys(self):
        """Auto-extract keys from payload using the selected body format."""
        try:
            payload_str = self._payloadArea.getText().strip()
            if not payload_str:
                return
            # Use selected format if available
            try:
                fmt = str(self._bodyFormatCombo.getSelectedItem())
                if fmt == "multipart/form-data":
                    boundary = self._boundaryField.getText().strip()
                    ct = "multipart/form-data; boundary=" + boundary if boundary else "multipart/form-data"
                elif fmt == "URL-encoded":
                    ct = "application/x-www-form-urlencoded"
                else:
                    ct = "application/json"
            except:
                ct = ""
            data = parse_body(payload_str, ct)
            if isinstance(data, dict) and data:
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysOrderField.getText().strip()
                if current != new_keys_str:
                    self._keysOrderField.setText(new_keys_str)
        except:
            pass

    def _tryFormatJson(self):
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
                "CipherKit - Save Error",
                JOptionPane.WARNING_MESSAGE
            )
            return

        self.snippet_manager.update_snippet(name, code)
        self._refreshAlgoList()
        JOptionPane.showMessageDialog(
            self._mainPanel,
            "Snippet '%s' saved successfully." % name,
            "CipherKit",
            JOptionPane.INFORMATION_MESSAGE
        )
        print("[*] Snippet saved: %s" % name)

    def _onLoadSnippet(self, event=None):
        names = self.snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel,
                "No snippets available.",
                "CipherKit - Load",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        selected = JOptionPane.showInputDialog(
            self._mainPanel,
            "Select a snippet to load:",
            "CipherKit - Load Snippet",
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
                "CipherKit",
                JOptionPane.INFORMATION_MESSAGE
            )
            return

        selected = JOptionPane.showInputDialog(
            self._mainPanel,
            "Select a snippet to delete:",
            "CipherKit - Delete Snippet",
            JOptionPane.WARNING_MESSAGE,
            None,
            names,
            names[0]
        )

        if selected:
            confirm = JOptionPane.showConfirmDialog(
                self._mainPanel,
                "Are you sure you want to delete '%s'?" % selected,
                "CipherKit - Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                self.snippet_manager.delete_snippet(str(selected))
                self._refreshAlgoList()
                print("[*] Snippet deleted: %s" % selected)

    def _refreshAlgoList(self):
        self._algoCombo.removeAllItems()
        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        for name in names:
            self._algoCombo.addItem(name)
        self._updatePasscodeFieldState()

    def _refreshCryptoAlgoList(self):
        self._cryptoAlgoCombo.removeAllItems()
        names = self.crypto_snippet_manager.get_all_names()
        if not names:
            self._cryptoAlgoCombo.addItem("(no algorithms -- add via Crypto Editor)")
        else:
            for name in names:
                self._cryptoAlgoCombo.addItem(name)
        self._updateCryptoFieldState()

    # -------------------------------------------------------------------------
    # Actions: Crypto Editor
    # -------------------------------------------------------------------------
    def _onSaveCryptoSnippet(self, event=None):
        name = self._cryptoSnippetNameField.getText().strip()
        enc  = self._cryptoEncArea.getText().strip()
        dec  = self._cryptoDecArea.getText().strip()
        if not name:
            JOptionPane.showMessageDialog(
                self._mainPanel, "Please enter an algorithm name.",
                "CipherKit - Save Error", JOptionPane.WARNING_MESSAGE
            )
            return
        self.crypto_snippet_manager.update_snippet(name, enc, dec)
        self._refreshCryptoAlgoList()
        JOptionPane.showMessageDialog(
            self._mainPanel, "Crypto snippet '%s' saved." % name,
            "CipherKit", JOptionPane.INFORMATION_MESSAGE
        )
        print("[*] Crypto snippet saved: %s" % name)

    def _onLoadCryptoSnippet(self, event=None):
        names = self.crypto_snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel, "No crypto snippets available.",
                "CipherKit - Load", JOptionPane.INFORMATION_MESSAGE
            )
            return
        selected = JOptionPane.showInputDialog(
            self._mainPanel, "Select a crypto snippet to load:",
            "CipherKit - Load Crypto Snippet", JOptionPane.PLAIN_MESSAGE,
            None, names, names[0]
        )
        if selected:
            snippet = self.crypto_snippet_manager.get_snippet(str(selected))
            if snippet:
                self._cryptoSnippetNameField.setText(str(selected))
                self._cryptoEncArea.setText(snippet.get("encrypt_code", ""))
                self._cryptoDecArea.setText(snippet.get("decrypt_code", ""))
                print("[*] Crypto snippet loaded: %s" % selected)

    def _onDeleteCryptoSnippet(self, event=None):
        names = self.crypto_snippet_manager.get_all_names()
        if not names:
            JOptionPane.showMessageDialog(
                self._mainPanel, "No crypto snippets to delete.",
                "CipherKit", JOptionPane.INFORMATION_MESSAGE
            )
            return
        selected = JOptionPane.showInputDialog(
            self._mainPanel, "Select a crypto snippet to delete:",
            "CipherKit - Delete Crypto Snippet", JOptionPane.WARNING_MESSAGE,
            None, names, names[0]
        )
        if selected:
            confirm = JOptionPane.showConfirmDialog(
                self._mainPanel, "Delete '%s'?" % selected,
                "CipherKit - Confirm Delete", JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                self.crypto_snippet_manager.delete_snippet(str(selected))
                self._refreshCryptoAlgoList()
                print("[*] Crypto snippet deleted: %s" % selected)

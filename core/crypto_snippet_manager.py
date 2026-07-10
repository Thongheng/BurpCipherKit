# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os

class CryptoSnippetManager(object):
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

    def requires_key(self, name):
        s = self.snippets.get(name, {})
        return s.get("requires_key", True)

    def requires_iv(self, name):
        s = self.snippets.get(name, {})
        return s.get("requires_iv", True)

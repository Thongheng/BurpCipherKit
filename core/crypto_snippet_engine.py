# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os, sys, hashlib, hmac, base64, time, traceback, itertools
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec


class CryptoSnippetEngine(object):
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
# AppSetting Manager: save/load AppSettings store complete configurations for different APIs/endpoints so you don't have to re-enter settings when switching between applications.
# =============================================================================

# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os, sys, hashlib, hmac, base64, time, traceback, itertools

from core.utils import _safe_encode

class SnippetManager(object):
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
            "    # _safe_encode wraps non-ASCII key/message (Improvement-7)\n"
            "    signature = hmac.new(\n"
            "        key.encode('utf-8') if isinstance(key, str) else key,\n"
            "        message.encode('utf-8') if isinstance(message, str) else message,\n"
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

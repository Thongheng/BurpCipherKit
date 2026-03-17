# CipherKit - Universal Crypto Toolkit for Burp Suite

**CipherKit** (formerly HashGen) is a flexible, modular cryptographic toolkit designed to generate hashes, signatures, and perform encryption/decryption using user-defined Python algorithms directly within **Burp Suite** (Jython).

## Features

*   **Hashing & Signatures**: Generate hashes (SHA256, HMAC, etc.) to sign your payloads dynamically.
*   **Encryption & Decryption**: Built-in AES-CBC-128 and AES-CBC-256, plus custom user-defined crypto routines via Java's `javax.crypto`.
*   **Key Finder**: Automatically discover the key order used to build a hash input string by brute-forcing field permutations against a known concatenated value.
*   **Preset System**: Save per-API configurations (algorithm, secret, keys order, crypto settings) as named presets. Presets auto-load when a matching URL pattern is detected in the request editor.
*   **Dynamic Algorithm Support**: Write implementation logic in Python and execute it on the fly. No need to restart the application. Supports both Hash generation and Crypto encryption/decryption routines.
*   **Snippet Managers**: Save, Load, and Edit your custom algorithms in the built-in editors (`snippets.json` for hashes, `crypto_snippets.json` for encryption/decryption).
*   **Inline Request Editor**: Generate hashes or encrypt/decrypt payloads directly from Burp's request viewers (Repeater, Proxy, etc.).

---

## Burp Suite Extension

### Prerequisites

*   **Burp Suite** (Professional or Community Edition)
*   **Jython standalone JAR** — download from [jython.org](https://www.jython.org/download)

### Installation

1.  In Burp Suite, go to **Extender > Options > Python Environment**
2.  Select the Jython standalone JAR file
3.  Go to **Extender > Extensions > Add**
4.  Extension type: **Python**
5.  Browse to `HashGenBurp.py`
6.  Confirm `[+] CipherKit extension loaded successfully` in the Output tab.

### Files

| File | Purpose |
|------|---------|
| `HashGenBurp.py` | Main extension source |
| `snippets.json` | Saved hash/signature algorithms (auto-created) |
| `crypto_snippets.json` | Saved encryption/decryption algorithms (auto-created) |
| `presets.json` | Saved per-API presets (auto-created) |

---

## Extension Views

The extension provides **two main views**:

### 1. Main CipherKit Tab

A dedicated tab in Burp's main tab bar with four sub-tabs:

*   **Hash** — Select a hash algorithm, enter a Secret, add Custom Data, set Keys Order, configure Hash Field, paste a JSON payload, and generate a hash. Includes a **Preset** selector at the top to save/load/delete named configurations.
*   **Crypto** — Select a crypto algorithm (AES-CBC-128, AES-CBC-256, or custom), enter a Key and IV, choose Encrypt/Decrypt mode, configure the target Field, paste a payload, and process it.
*   **Hash Editor** — Write, save, load, and delete custom hash algorithms.
*   **Crypto Editor** — Write, save, load, and delete custom encryption/decryption algorithms.

### 2. Inline Request Editor Tab

A **"CipherKit" tab** that appears alongside **Pretty / Raw / Hex** in every request viewer (Repeater, Proxy, etc.). Optimized for inline workflow with three sub-tabs:

*   **Hash** — Algorithm, Secret, Custom Data, Keys Order, Hash Field, Generate / Gen & Inject / Save Preset buttons.
*   **Crypto** — Mode, Algorithm, Key, IV, Field, Run Crypto / Run & Inject buttons. Auto-encrypts on value change with debounce.
*   **Key Finder** — Body Format, Additional Values, Known String, Find Key Order button, with Parsed Fields and Results panels.

**Auto-sync**: Config set in the main tab automatically syncs to the inline tab when a request is loaded.

**Auto-preset**: When a request is loaded, the URL path is matched against saved presets. If a match is found, all fields are auto-populated.

---

## Preset System

Presets save complete configurations for different APIs/endpoints so you don't have to re-enter settings when switching between applications.

### Saving a Preset

**From the main tab:**
1.  Configure all your hash/crypto settings
2.  Click **Save** next to the Preset dropdown
3.  Enter a name (e.g. "App A - /api/user")
4.  Enter a URL pattern for auto-matching (e.g. `/api/user`)

**From the inline tab:**
1.  Configure your settings in the request editor
2.  Click **Save Preset** button
3.  Enter a name and URL pattern (pre-filled with current request path)

### Auto-Loading

When you open a request in the editor, CipherKit extracts the URL path and checks it against all preset patterns. If a match is found, all fields (algorithm, secret, keys order, crypto key/IV, etc.) are automatically populated.

### Preset Data

Presets are stored in `presets.json` with this structure:

```json
{
  "App A - /api/user": {
    "match_pattern": "/api/user",
    "hash": {
      "algorithm": "HMAC-SHA256",
      "secret": "mysecret",
      "custom_data": {"API": "abc123"},
      "keys_order": "user, id, token",
      "hash_field": "hash"
    },
    "crypto": {
      "mode": "Encrypt",
      "algorithm": "AES-CBC-128",
      "key": "mykey",
      "iv": "",
      "field": "data"
    }
  }
}
```

---

## Key Finder

The Key Finder helps you discover the field concatenation order used to build a hash input string.

### How to Use

1.  Open the **Key Finder** tab (in the main CipherKit tab or inline request editor)
2.  The request body is auto-parsed into key-value pairs in **Parsed Fields**
3.  Add any **Additional Values** not in the request body (e.g. an API key the app injects client-side)
4.  Paste the **Known Concatenated String** — the value you know the server uses as hash input
5.  Click **Find Key Order**

### Example

Given a request body:
```json
{"id": "123", "code": "abc", "name": "heng"}
```

And a known concatenated string: `heng123abc`

The Key Finder will output:
```
1 match found:
  Key order  : name, id, code
  Concat     : heng123abc
```

### No Match

When no exact permutation match is found, the tool shows:
- Which field values **were found** in the known string
- **Unknown segments** — parts of the known string not matching any field value (useful for identifying hidden values like API keys)

---

## Writing Custom Algorithms

### Hash / Signature Snippets

Your snippet **MUST** define a `generate` function:

```python
def generate(payload, passcode, custom_data=None, key_order=None):
    """
    payload:     dict  - Merged JSON data (request body + Custom Data)
    passcode:    str   - Secret key/IV
    custom_data: dict  - Dictionary of custom data {key: value} (optional)
    key_order:   list  - Optional ordered list of keys to sign
    """
    import hashlib
    import hmac

    # Build your message string from payload using key_order
    # ...

    # Sign and return
    return hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
```

### Crypto (Encryption/Decryption) Snippets

Your snippet **MUST** define both `encrypt` and `decrypt` functions:

```python
def encrypt(input_text, key_str, iv_str):
    """
    input_text: str - The plaintext to encrypt
    key_str:    str - The encryption key
    iv_str:     str - The initialization vector (optional)
    """
    # Java crypto classes available: Cipher, SecretKeySpec, IvParameterSpec
    # Return encrypted string (e.g. Base64 encoded)
    pass

def decrypt(input_text, key_str, iv_str):
    """
    input_text: str - The ciphertext (e.g. Base64) to decrypt
    key_str:    str - The decryption key
    iv_str:     str - The initialization vector (optional)
    """
    # Return decrypted plaintext string
    pass
```

### Built-in Algorithms

| Algorithm | Key Size | IV Size | Notes |
|-----------|----------|---------|-------|
| AES-CBC-128 | 16 bytes (UTF-8) | 16 bytes (blank = reuse key) | PKCS5 padding |
| AES-CBC-256 | 32 bytes (UTF-8) | 16 bytes (required) | PKCS5 padding |

### Snippet Flags

Custom crypto snippets support these flags in the editor:

*   `requires_key` — If true, the Key field is editable. If false, it's dimmed.
*   `requires_iv` — If true, the IV field is editable. If false, it's dimmed.

---

## Supported Body Formats

*   **JSON** — Parsed as key-value dict, pretty-printed in editor
*   **URL-encoded** — `key1=value1&key2=value2` format
*   **Multipart/form-data** — Auto-detects boundary from Content-Type header or body

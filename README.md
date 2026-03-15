# CipherKit - Universal Crypto Toolkit for Burp Suite

**CipherKit** (formerly HashGen) is a flexible, modular cryptographic toolkit designed to generate hashes, signatures, and perform encryption/decryption using user-defined Python algorithms directly within **Burp Suite** (Jython).

## Features

*   **Hashing & Signatures**: Generate hashes (SHA256, HMAC, etc.) to sign your payloads dynamically.
*   **Encryption & Decryption**: Support for symmetric and asymmetric encryption routines using Java's built-in `javax.crypto` (e.g., AES-CBC-128).
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

### Extension Views

The extension provides **two main views**:

#### 1. Main CipherKit Tab

A dedicated tab in Burp's main tab bar with four sub-tabs:

*   **Hash** — Select a hash algorithm, enter a PassCode, add Custom Data, set Keys Order, paste a JSON payload, and generate a hash.
*   **Crypto** — Select a crypto algorithm, enter a Key and IV, choose Encrypt/Decrypt mode, paste a payload, and process it.
*   **Hash Editor** — Write, save, load, and delete custom hash algorithms.
*   **Crypto Editor** — Write, save, load, and delete custom encryption/decryption algorithms.

#### 2. Inline Request Editor Tab

A **"CipherKit" tab** that appears alongside **Pretty / Raw / Hex** in every request viewer (Repeater, Proxy, etc.). Optimized for inline workflow.

*   **Editable request body** — Modify the request body directly (JSON, Form-Urlencoded, Multipart).
*   **Hash Config** — Generate a hash and inject it into the request body (into the field specified by "Hash Field").
*   **Crypto Config** — Encrypt or Decrypt the request body. Supports full body replacement or specific field injection.

## Writing Custom Algorithms

### Hash / Signature Snippets

Your snippet **MUST** define a `generate` function with the following signature:

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

    # 1. Parse Passcode
    if len(passcode) < 16:
        raise ValueError("PassCode must be at least 16 characters long.")
    iv = passcode[-16:]
    key = passcode[:-16]

    # ... Build your message string ...

    # 5. Sign
    return hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
```

### Crypto (Encryption/Decryption) Snippets

Your snippet **MUST** define both an `encrypt` and `decrypt` function with the following signatures:

```python
def encrypt(input_text, key_str, iv_str):
    """
    input_text: str - The plaintext to encrypt
    key_str:    str - The encryption key
    iv_str:     str - The initialization vector (optional)
    """
    # Java crypto implementations are exposed in the global scope
    # e.g., Cipher, SecretKeySpec, IvParameterSpec
    # Return your encrypted string (e.g. Base64 encoded)
    pass

def decrypt(input_text, key_str, iv_str):
    """
    input_text: str - The ciphertext (e.g. Base64) to decrypt
    key_str:    str - The decryption key
    iv_str:     str - The initialization vector (optional)
    """
    # Return your decrypted plaintext string
    pass
```
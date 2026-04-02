# CipherKit — Universal Crypto Toolkit for Burp Suite

**CipherKit** is a modular cryptographic toolkit for **Burp Suite** (Jython) that generates hashes, signatures, and performs encryption/decryption using user-defined Python algorithms.

---

## Features

- **Hashing & Signatures** — HMAC-SHA256, SHA256, and custom algorithms to sign payloads dynamically.
- **Encryption & Decryption** — Built-in AES-CBC-128/256, plus custom algorithms via `javax.crypto`.
- **Key Finder** — Brute-force the field concatenation order used to build a hash input against a known value. Runs in a background thread.
- **AppSetting System** — Save per-API configs (algorithm, secret, sign order, crypto settings) with URL pattern matching for auto-load.
- **Intruder Auto-Rehash** — Integrates with Burp's Session Handling Rules to automatically recalculate hash/signature fields on every Intruder or Repeater request.
- **Custom Snippet Editors** — Write and save hash and crypto algorithms in Python with syntax validation before saving.
- **Inline Request Editor** — Generate hashes or encrypt/decrypt directly inside Burp's Repeater, Proxy, and other request viewers.

---

## Installation

**Prerequisites:** Burp Suite (Pro or Community) + [Jython standalone JAR](https://www.jython.org/download)

1. In Burp go to **Extender › Options › Python Environment** and select your Jython JAR.
2. Go to **Extender › Extensions › Add**, set type to **Python**, and select `HashGenBurp.py`.
3. Confirm `[+] CipherKit extension loaded successfully` in the Output tab.

| File | Purpose |
|------|---------|
| `HashGenBurp.py` | Main extension entry point |
| `snippets.json` | Saved hash/signature algorithms |
| `crypto_snippets.json` | Saved encryption/decryption algorithms |
| `app_settings.json` | Saved per-API app settings |

---

## Main Tab Overview

A **CipherKit** tab is added to Burp's main tab bar with the following sub-tabs:

- **Hash** — Select an algorithm, enter Secret/Custom Data/Sign Order, paste a payload, and click **Generate**.
- **Crypto** — Encrypt or decrypt a payload field using a saved crypto algorithm.
- **Key Finder** — Paste a request body, add extra fields if needed, enter the known concatenated string, and click **Find Key Order**.
- **Hash Editor** — Write, save, load, and delete custom hash snippets (syntax-checked on save).
- **Crypto Editor** — Write, save, load, and delete custom crypto snippets with separate Encrypt/Decrypt functions (syntax-checked on save).
- **AppSetting** — View, save, update, and delete named app settings with a structured config summary.

---

## Inline Request Editor

A **CipherKit** tab appears alongside Pretty/Raw/Hex in every request viewer.

- **Hash sub-tab** — Same as the main Hash tab plus a **Gen & Inject** button that writes the hash directly into the request body.
- **Crypto sub-tab** — Auto-decrypts the configured field when the tab is opened. Edits to the plaintext are auto-re-encrypted after an 800 ms debounce (toggleable per-tab or globally).
- **AppSetting sub-tab** — Shows the current URL, lets you load or save an app setting, and displays the last auto-load result.
- **Auto-app-setting** — On request load, CipherKit matches the URL path against saved endpoint patterns (supports glob wildcards, e.g. `/api/user/*`) and auto-populates all fields if a match is found.

---

## Intruder Auto-Rehash

1. In Burp go to **Project Options › Sessions › Session Handling Rules › Add**.
2. Under **Rule Actions**, click **Add › Invoke a Burp extension** and select **CipherKit - Auto-Rehash**.
3. Set the **Scope** to the relevant tools (Intruder, Repeater, etc.) and configure the URL scope.

On each matching request, CipherKit re-runs the app setting's hash snippet, injects the result into the configured output field, and logs to the extension Output tab:
```
[CipherKit] Auto-Rehash: app_setting='MyApp' pattern='/api/login' hash_field='sign' value='a3f9c2...'
```
> An AppSetting with at least one endpoint pattern must be saved for the target URL before use.

---

## AppSetting Data Format

```json
{
  "MyApp": {
    "algorithm": "ABA HMAC SHA256",
    "secret": "mysecretkey",
    "custom_data": {"API": "abc123"},
    "hash_field": "sign",
    "crypto": {
      "algorithm": "AES-CBC-128",
      "key": "myencryptionkey!",
      "iv": "",
      "field": "data"
    },
    "endpoints": {
      "/api/login":   { "keys_order": "user, password, timestamp" },
      "/api/user/*":  { "keys_order": "id, action, timestamp" }
    }
  }
}
```

---

## Writing Custom Algorithms

### Hash Snippet

Must define a `generate` function. Returns either a plain string or a `(result, debug_log)` tuple — the debug log is shown in the Debug Output area.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `payload` | `dict` | Merged dict of request body fields + custom_data |
| `passcode` | `str` | Value from the Secret field |
| `custom_data` | `dict` | Extra key:value pairs from the Custom Data panel |
| `key_order` | `list` | Ordered key names from the Sign Order field (or `None`) |

**Example — HMAC-SHA256:**
```python
def generate(payload, passcode, custom_data=None, key_order=None):
    import hmac, hashlib

    # Use explicit key order if provided, otherwise use all payload keys except 'hash'
    keys_to_sign = key_order or [k for k in payload.keys() if k != 'hash']

    # Concatenate values in order
    concat_str = ""
    for k in keys_to_sign:
        concat_str += str(payload.get(k, ""))

    # Sign and return result + debug info
    signature = hmac.new(
        passcode.encode('utf-8'),
        concat_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    debug_log = "Keys: %s\nMessage: '%s'\nResult: %s" % (keys_to_sign, concat_str, signature)
    return signature, debug_log
```

> Set `requires_key: false` in `snippets.json` to grey out the Secret field for keyless algorithms.

---

### Crypto Snippet

Must define both `encrypt` and `decrypt` functions in the **same save** (written in separate code areas in the Crypto Editor tab). Both must return a string.

**Parameters:**

| Function | Parameters | Returns |
|----------|-----------|---------|
| `encrypt` | `plaintext` (str), `key` (str), `iv` (str) | Base64 ciphertext string |
| `decrypt` | `ciphertext_b64` (str), `key` (str), `iv` (str) | Plaintext string |

`Cipher`, `SecretKeySpec`, `IvParameterSpec`, and `base64` are pre-imported and available in scope.

**Example — AES-CBC-128:**
```python
def encrypt(plaintext, key, iv):
    # key: 16-char UTF-8 string (AES-128)
    # iv:  16-char UTF-8 string; leave blank to reuse key bytes
    key_bytes = key.encode('UTF-8')
    iv_bytes  = iv.encode('UTF-8') if iv and iv.strip() else key_bytes

    secret_key = SecretKeySpec(key_bytes, 'AES')
    cipher     = Cipher.getInstance('AES/CBC/PKCS5Padding')
    cipher.init(Cipher.ENCRYPT_MODE, secret_key, IvParameterSpec(iv_bytes))

    encrypted = cipher.doFinal(plaintext.encode('UTF-8'))
    return base64.b64encode(bytes(bytearray(encrypted)))
```

```python
def decrypt(ciphertext_b64, key, iv):
    # key: 16-char UTF-8 string (AES-128)
    # iv:  16-char UTF-8 string; leave blank to reuse key bytes
    key_bytes = key.encode('UTF-8')
    iv_bytes  = iv.encode('UTF-8') if iv and iv.strip() else key_bytes

    secret_key = SecretKeySpec(key_bytes, 'AES')
    cipher     = Cipher.getInstance('AES/CBC/PKCS5Padding')
    cipher.init(Cipher.DECRYPT_MODE, secret_key, IvParameterSpec(iv_bytes))

    decrypted = cipher.doFinal(base64.b64decode(ciphertext_b64))
    return bytearray(decrypted).decode('UTF-8')
```

### Built-in Algorithms

| Algorithm | Key | IV |
|-----------|-----|----|
| AES-CBC-128 | 16-byte UTF-8 | 16-byte UTF-8 (blank = reuse Key) |
| AES-CBC-256 | 32-byte UTF-8 | 16-byte UTF-8 (required) |

---

## Supported Body Formats

| Format | Content-Type |
|--------|-------------|
| JSON | `application/json` |
| URL-encoded | `application/x-www-form-urlencoded` |
| Multipart | `multipart/form-data` (boundary auto-detected) |

---

## Security Notes

- Custom snippet code runs with a restricted `__builtins__` allowlist — `os.system()`, file writes, and network calls are blocked.
- CipherKit makes no external connections. All processing is local to the JVM.
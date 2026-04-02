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

```python
def generate(payload, passcode, custom_data=None, key_order=None):
    # payload: merged dict of request body + custom_data
    # Returns a string or (result, debug_log) tuple
    import hmac, hashlib
    keys = key_order or [k for k in payload.keys() if k != 'sign']
    message = "".join(str(payload.get(k, "")) for k in keys)
    sig = hmac.new(passcode.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
    return sig, "Keys: %s\nMessage: %s" % (keys, message)
```

### Crypto Snippet

```python
def encrypt(plaintext, key, iv):
    # Must return a string (e.g. Base64 ciphertext)
    ...

def decrypt(ciphertext_b64, key, iv):
    # Must return a string (plaintext)
    ...
```

Java crypto classes (`Cipher`, `SecretKeySpec`, `IvParameterSpec`) and `base64` are available.

### Built-in Algorithms

| Algorithm | Key | IV |
|-----------|-----|----|
| AES-CBC-128 | 16 bytes | 16 bytes (blank = reuse Key) |
| AES-CBC-256 | 32 bytes | 16 bytes (required) |

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
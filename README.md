# CipherKit — Universal Crypto Toolkit for Burp Suite

**CipherKit** is a flexible, modular cryptographic toolkit that generates hashes, signatures, and performs encryption/decryption using user-defined Python algorithms directly inside **Burp Suite** (Jython).

---

## Features

- **Hashing & Signatures** — Generate HMAC-SHA256, SHA256, and custom signature algorithms to sign payloads dynamically.
- **Encryption & Decryption** — Built-in AES-CBC-128 and AES-CBC-256, plus custom algorithms via Java's `javax.crypto`.
- **Key Finder** — Discover the field concatenation order used to build a hash input by brute-forcing permutations against a known value. Runs in a background thread — Burp stays responsive.
- **AppSetting System** — Save per-API configurations (algorithm, secret, sign order, crypto settings) as named app settings. Auto-loads when a matching URL pattern is detected.
- **Intruder Auto-Rehash** — Integrates with Burp's Session Handling Rules to automatically recalculate the hash/signature field on every Intruder or Repeater request. No manual clicking required.
- **Custom Snippet Editors** — Write and save hash and crypto algorithms in Python. Syntax is validated before saving.
- **Inline Request Editor** — Generate hashes or encrypt/decrypt payloads directly inside Burp's Repeater, Proxy, and other request viewers.

---

## Installation

### Prerequisites

- Burp Suite (Professional or Community Edition)
- Jython standalone JAR — download from [jython.org](https://www.jython.org/download)

### Steps

1. In Burp Suite go to **Extender › Options › Python Environment** and select your Jython JAR.
2. Go to **Extender › Extensions › Add**.
3. Set Extension type to **Python** and browse to `HashGenBurp.py`.
4. Confirm `[+] CipherKit extension loaded successfully` in the Output tab.

### Files

| File | Purpose |
|------|---------|
| `HashGenBurp.py` | Main extension source |
| `snippets.json` | Saved hash/signature algorithms (auto-created) |
| `crypto_snippets.json` | Saved encryption/decryption algorithms (auto-created) |
| `app_settings.json` | Saved per-API app settings (auto-created) |

---

## Main CipherKit Tab

A dedicated tab in Burp's main tab bar with the following sub-tabs:

### Hash Tab

| Field | Description |
|-------|-------------|
| **Algorithm** | Select a saved hash snippet |
| **Secret** | The signing key or passphrase |
| **Custom Data** | Extra key:value pairs injected into the payload before signing (e.g. an API key not in the request body) |
| **Sign Order** | Comma-separated list of field names defining the concatenation order (e.g. `user, id, token`) |
| **Output Field** | The JSON key name where the generated hash will be injected (default: `hash`) |
| **Body Format** | JSON, URL-encoded, or multipart/form-data |
| **Payload** | Paste the full request body here |

Buttons:
- **Generate** — Compute and display the hash in the Result Hash area.
- **Debug Output** — Shows any debug information returned by your snippet.

### Crypto Tab

| Field | Description |
|-------|-------------|
| **Mode** | Encrypt or Decrypt |
| **Algorithm** | Select a saved crypto snippet (AES-CBC-128, AES-CBC-256, or custom) |
| **Key** | Encryption/decryption key (UTF-8 string) |
| **IV** | Initialization vector. Leave blank to reuse the Key bytes as IV (AES-CBC-128 default) |
| **Field** | JSON key to read input from / write output to |

Button: **Run Crypto**

### Key Finder Tab

See [Key Finder](#key-finder) section below.

### Hash Editor Tab

Write, save, load, and delete custom hash/signature algorithms. The code is **syntax-checked** before saving — any error is shown with the line number.

### Crypto Editor Tab

Write, save, load, and delete custom encryption/decryption algorithms. Two labelled code areas: **Encrypt Function** and **Decrypt Function**. Both are syntax-checked before saving.

### AppSetting Tab

View, load, save, update, and delete named app settings. Each setting displays a structured summary showing its algorithm, secret, crypto config, and all saved endpoint patterns.

---

## Inline Request Editor Tab

A **CipherKit** tab appears alongside Pretty / Raw / Hex in every request viewer (Repeater, Proxy, etc.).

### Hash Sub-tab

Same fields as the main Hash tab. Extra buttons:
- **Generate** — Compute the hash and show in the output area.
- **Gen & Inject** — Compute the hash and inject it directly into the request body under the **Output Field** key.

### Crypto Sub-tab

- **Auto-decrypt on tab switch** — When you click the Crypto tab, the configured body field is automatically decrypted and shown in the output area. No manual button press needed.
- **Auto-encrypt on edit** — After decrypting, any edits to the plaintext output are automatically re-encrypted and written back into the request body after an 800 ms debounce delay.
- The **Auto-encrypt on edit** checkbox lets you toggle this behaviour per-tab.
- The global **Auto-encrypt on edit** toggle in the bottom bar disables it session-wide.

### Key Finder Sub-tab

Compact version of the Key Finder. Body is auto-parsed when you open the tab.

### AppSetting Sub-tab

- Shows the current request URL.
- Lets you load an app setting or save the current config + URL as a new endpoint.
- **Status** field shows the last auto-load result (e.g. `Auto-loaded: MyApp / /api/login`).

### Auto-sync

Config entered in the main tab is automatically copied to the inline tab when a request is loaded.

### Auto-app-setting

When a request is loaded in the editor, CipherKit extracts the URL path and checks it against all saved app setting endpoint patterns (supports glob wildcards, e.g. `/api/user/*`). If a match is found, all fields are auto-populated.

---

## Intruder Auto-Rehash

CipherKit registers itself as a **Session Handling Action** so that Burp's Session Handling Rules can automatically rehash requests during Intruder scans or Repeater sends — without any manual intervention.

### Setup

1. In Burp go to **Project Options › Sessions › Session Handling Rules**.
2. Click **Add** to create a new rule.
3. Under **Rule Actions**, click **Add › Invoke a Burp extension**.
4. Select **CipherKit - Auto-Rehash** from the action list.
5. Set the **Scope** to the relevant tool(s): Intruder, Repeater, or Scanner.
6. Configure the URL scope to match your target.

### How it works

When a request fires through the rule, CipherKit:

1. Extracts the request URL path.
2. Looks up a matching app setting (exact substring or glob match against saved endpoint patterns).
3. Parses the request body.
4. Re-runs the app setting's hash snippet with the current body values, secret, custom data, and sign order.
5. Injects the new hash value into the configured **Output Field** in the body.
6. Sends the updated request.

If no app setting matches the URL, the request is passed through unchanged.

### Requirements

- An app setting must be saved for the target URL before using Auto-Rehash (see [AppSetting System](#appsetting-system)).
- The app setting must have at least one endpoint pattern configured.

### Console output

Every rehash logs to Burp's extension Output tab:

```
[CipherKit] Auto-Rehash: app_setting='MyApp' pattern='/api/login' hash_field='sign' value='a3f9c2...'
```

---

## AppSetting System

AppSettings store complete configurations for a specific API so you don't re-enter settings when switching between targets.

### Saving an AppSetting

**From the main tab:**
1. Configure all Hash and Crypto settings.
2. Go to the **AppSetting** sub-tab and click **Save New**.
3. Enter a name (e.g. `MyApp`).

**From the inline editor tab:**
1. Configure settings in the request editor.
2. Click the **AppSetting** sub-tab.
3. Enter a **Sign Order** for the current endpoint if needed.
4. Click **Save Endpoint** — the current URL path is pre-filled as the pattern.

### Glob Patterns

Endpoint URL patterns support `fnmatch`-style wildcards:

| Pattern | Matches |
|---------|---------|
| `/api/user` | Exactly `/api/user` |
| `/api/user/*` | `/api/user/123`, `/api/user/profile`, etc. |
| `/api/*/login` | `/api/v1/login`, `/api/v2/login`, etc. |

### AppSetting Data Format

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
      "/api/login": { "keys_order": "user, password, timestamp" },
      "/api/user/*": { "keys_order": "id, action, timestamp" }
    }
  }
}
```

---

## Key Finder

Reverse-engineers the field concatenation order used to build a hash input string.

### How to Use

1. Open the **Key Finder** tab.
2. Paste the request body and click **Parse Body** — fields are extracted into **Parsed Fields**.
3. Add any **Extra Fields** not in the request body (e.g. a static API key the client injects).
4. Paste the **Known Concatenated String** — the value you know the server signs.
5. Click **Find Key Order**. Results appear in the right panel.

The brute-force runs in a **background thread** so Burp remains responsive.

### Example

Request body:
```json
{"id": "123", "code": "abc", "name": "heng"}
```

Known concatenated string: `heng123abc`

Result:
```
1 match found:
  Key order  : name, id, code
  Concat     : heng123abc
```

Copy the key order into the **Sign Order** field in the Hash tab.

### No Match Diagnostics

When no match is found, the tool shows:
- Which field values **were** found inside the known string.
- **Unknown segments** — parts of the known string that don't match any field value (useful for spotting hidden static values or timestamps).

---

## Writing Custom Algorithms

### Hash / Signature Snippets

Define a `generate` function. It can return a plain string or a `(result, debug_log)` tuple.

```python
def generate(payload, passcode, custom_data=None, key_order=None):
    """
    payload:     dict  - Merged dict of request body fields + custom_data
    passcode:    str   - The Secret field value
    custom_data: dict  - Extra Fields key:value pairs
    key_order:   list  - Ordered list of keys to sign (from Sign Order field)
    """
    import hmac, hashlib

    keys = key_order or [k for k in payload.keys() if k != 'sign']
    message = "".join(str(payload.get(k, "")) for k in keys)

    sig = hmac.new(
        passcode.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    debug = "Keys: %s\nMessage: %s" % (keys, message)
    return sig, debug
```

### Crypto Snippets

Define both `encrypt` and `decrypt` functions. Java crypto classes (`Cipher`, `SecretKeySpec`, `IvParameterSpec`) and `base64` are available in scope.

```python
def encrypt(plaintext, key, iv):
    # key: str, iv: str (may be empty)
    # Must return a string (e.g. Base64 ciphertext)
    kb = key.encode('UTF-8')
    ib = iv.encode('UTF-8') if iv else kb[:16]
    sk = SecretKeySpec(kb, 'AES')
    c  = Cipher.getInstance('AES/CBC/PKCS5Padding')
    c.init(1, sk, IvParameterSpec(ib))
    return base64.b64encode(bytes(bytearray(c.doFinal(plaintext.encode('UTF-8')))))

def decrypt(ciphertext_b64, key, iv):
    # Must return a string (plaintext)
    kb = key.encode('UTF-8')
    ib = iv.encode('UTF-8') if iv else kb[:16]
    sk = SecretKeySpec(kb, 'AES')
    c  = Cipher.getInstance('AES/CBC/PKCS5Padding')
    c.init(2, sk, IvParameterSpec(ib))
    return bytearray(c.doFinal(base64.b64decode(ciphertext_b64))).decode('UTF-8')
```

### Built-in Algorithms

| Algorithm | Key Size | IV Size | Notes |
|-----------|----------|---------|-------|
| AES-CBC-128 | 16 bytes (UTF-8) | 16 bytes (blank = reuse Key) | PKCS5 padding |
| AES-CBC-256 | 32 bytes (UTF-8) | 16 bytes (required) | PKCS5 padding |

> **Key/IV length errors** show the exact byte count received, e.g. `"AES Key must be 16, 24, or 32 UTF-8 bytes — got 10 byte(s)."` to help diagnose mismatches quickly.

---

## Supported Body Formats

| Format | Content-Type | Notes |
|--------|-------------|-------|
| JSON | `application/json` | Pretty-printed in editor; default format |
| URL-encoded | `application/x-www-form-urlencoded` | Full percent-decode (`%20`, `%2F`, etc.) |
| Multipart | `multipart/form-data` | Boundary auto-detected from body if not in header |

---

## Security Notes

- **Snippet sandbox** — Custom snippet code runs with a restricted `__builtins__` allowlist. `os.system()`, file writes, and network calls are blocked inside snippet execution.
- **No outbound connections** — CipherKit makes no external calls. All processing is local to the JVM.

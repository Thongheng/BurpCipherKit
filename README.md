# CipherKit — Universal Crypto Toolkit for Burp Suite

**CipherKit** is a modular cryptographic toolkit for **Burp Suite** (Jython) that allows you to dynamically sign, hash, encrypt, and decrypt request payloads using built-in or custom Python algorithms.

---

## 🚀 Key Features

* **Inline Request Editor** — Sign, hash, and encrypt/decrypt directly inside Burp's Repeater, Proxy, or Intruder tabs using the custom **CipherKit** panel.
* **AppSetting System** — Save configurations (secret, sign order, crypto parameters, and custom data overrides) per-API or per-endpoint using URL pattern matching (e.g., `/api/v3/*`).
* **Auto-Rehash Session Handler** — Automatically recalculate signatures and hash fields in background request pipelines (Repeater, Intruder, scanner, etc.) using Burp Session Handling Rules.
* **Key Finder** — Brute-force field concatenation orders against a known signature to easily reverse-engineer API sign order schemes.
* **Custom Python Snippets** — Write your own hash/signature and crypto functions directly in Burp, validated and compiled on the fly.

---

## 🛠️ Installation & Setup

1. **Prerequisite:** Download the [Jython standalone JAR](https://www.jython.org/download).
2. Configure Jython in Burp: **Extender › Options › Python Environment** and select the Jython JAR.
3. Add the extension: **Extender › Extensions › Add**, set Type to **Python**, and select `HashGenBurp.py`.

---

## 💡 Key Workflows

### 1. Endpoint-Specific Configuration (AppSetting)
Save sign-orders, custom data, and crypto keys mapped to URL patterns.
* Under the **AppSetting** tab, name your app and configure its shared parameters.
* Define endpoint-level sign orders and custom data (e.g. `token` overrides for specific endpoints like `/api/v3/pay`).
* These settings auto-load in the inline editor when you browse requests matching the URL pattern.

### 2. Intruder & Scanner Auto-Signing (Auto-Rehash)
1. Go to **Project Options › Sessions › Session Handling Rules › Add**.
2. Under **Rule Actions**, add **Invoke a Burp extension** and select **CipherKit - Auto-Rehash**.
3. Set the Scope to Intruder/Repeater and target URLs. Every sent request will automatically re-calculate and inject signatures.

---

## 🐍 Writing Custom Snippets

### A. Custom Hash/Signature
Save python snippets under **Hash Editor**. The script must define `generate(payload, passcode, custom_data=None, key_order=None)`.

```python
def generate(payload, passcode, custom_data=None, key_order=None):
    import hmac, hashlib
    # Order fields according to the Sign Order settings
    keys = key_order or [k for k in payload.keys() if k != 'hash']
    msg = "".join(str(payload.get(k, "")) for k in keys)
    
    # Calculate HMAC-SHA256
    sig = hmac.new(passcode.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return sig, "Debug Log Info..."
```

### B. Custom Encryption/Decryption
Save python snippets under **Crypto Editor**. Define `encrypt` and `decrypt` functions in the same snippet.

```python
def encrypt(plaintext, key, iv):
    # key & iv are UTF-8 strings
    secret_key = SecretKeySpec(key.encode(), 'AES')
    cipher = Cipher.getInstance('AES/CBC/PKCS5Padding')
    cipher.init(Cipher.ENCRYPT_MODE, secret_key, IvParameterSpec(iv.encode()))
    encrypted = cipher.doFinal(plaintext.encode())
    return base64.b64encode(bytes(bytearray(encrypted)))

def decrypt(ciphertext_b64, key, iv):
    secret_key = SecretKeySpec(key.encode(), 'AES')
    cipher = Cipher.getInstance('AES/CBC/PKCS5Padding')
    cipher.init(Cipher.DECRYPT_MODE, secret_key, IvParameterSpec(iv.encode()))
    decrypted = cipher.doFinal(base64.b64decode(ciphertext_b64))
    return bytearray(decrypted).decode()
```

*(Note: `Cipher`, `SecretKeySpec`, `IvParameterSpec`, and `base64` are pre-imported in the Jython compiler scope)*
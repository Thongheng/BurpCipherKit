# HashGen - Universal Crypto Tool

**HashGen** is a flexible, modular cryptographic tool designed to generate hashes and signatures using user-defined Python algorithms directly within **Burp Suite** (Jython).

## Features

*   **Dynamic Algorithm Support**: Write implementation logic in Python and execute it on the fly. No need to restart the application.
*   **Snippet Manager**: Save, Load, and Edit your custom algorithms in the built-in editor.

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
6.  Confirm `[+] HashGen extension loaded successfully` in the Output tab

### Extension Views

The extension provides **two views**:

#### 1. Main HashGen Tab

A dedicated tab in Burp's main tab bar with two sub-tabs:

*   **Generator** — Select algorithm, enter PassCode, add custom data, set keys order, paste JSON payload, and generate hash.
*   **Snippet Editor** — Write, save, load, and delete custom algorithms.

#### 2. Inline Request Editor Tab

A **"HashGen" tab** that appears alongside **Pretty / Raw / Hex** in every request viewer (Repeater, Proxy, etc.). Optimized for inline workflow:

*   **Editable request body** — modify the JSON directly
*   **Generate** — compute the hash and display it
*   **Gen & Inject** — compute the hash and inject it into the JSON body (into the field specified by "Hash Field")

## Writing Custom Algorithms

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

    # 2. Determine Keys to Sign
    keys = key_order if key_order else [k for k in payload.keys() if k != 'hash']

    # 3. Concat Values
    data_str = ""
    for k in keys:
        data_str += str(payload.get(k, ""))

    # 4. Create signature
    msg = iv + data_str
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
```
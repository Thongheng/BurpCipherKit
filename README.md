# HashGen - Universal Crypto Tool

**HashGen** is a flexible, modular cryptographic tool designed to generate hashes and signatures using user-defined Python algorithms. Available as both a **standalone desktop app** (CustomTkinter) and a **Burp Suite extension** (Jython).

## Features

*   **Dynamic Algorithm Support**: Write implementation logic in Python and execute it on the fly. No need to restart the application.
*   **Snippet Manager**: Save, Load, and Edit your custom algorithms in the built-in editor.
*   **Custom Data Fields**: Add multiple custom data values (API keys, tokens, etc.) that get passed to your snippet. Click **[+]** to add more fields.
*   **Auto-Magic JSON**:
    *   **Auto-Format**: Pasting messy JSON payload automatically pretty-prints it.
    *   **Auto-Extract Keys**: Automatically extracts keys from the JSON payload to populate the "Keys Order" field.
*   **Standard Library Injection**: Algorithms have access to `hashlib`, `hmac`, `base64`, `json`, and `time` automatically.

---

## Standalone Desktop App

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/HashGen.git
    cd HashGen
    ```

2.  Install dependencies:
    ```bash
    pip install customtkinter
    ```

### Usage

```bash
python3 HashGen.py
```

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

*   **Compact config bar** — Algorithm, PassCode, Custom Data, Keys Order, Hash Field
*   **Editable request body** — modify the JSON directly
*   **Generate** — compute the hash and display it
*   **Gen & Inject** — compute the hash and inject it into the JSON body (into the field specified by "Hash Field")
*   **Keys Order is preserved** — once you set a custom keys order, it won't be overwritten when the body changes
*   **Config syncs** from the main tab — set your PassCode once, and it auto-fills in every inline tab

#### 3. Right-Click Context Menu

Right-click any request in Proxy/Repeater > **"Send to HashGen"** to auto-populate the Generator's JSON Payload field.

---

## Writing Custom Algorithms

Your snippet **MUST** define a `generate` function with the following signature:

```python
def generate(payload, passcode, custom_data=None, key_order=None):
    """
    payload:     dict  - JSON data from the request body
    passcode:    str   - Secret key/IV
    custom_data: list  - List of custom data strings (API keys, tokens, etc.)
    key_order:   list  - Optional ordered list of keys to sign
    """
    import hashlib
    import hmac

    # Get custom data values
    api_key = custom_data[0] if custom_data and len(custom_data) > 0 else ""

    # Use provided key order or default to sorted keys
    keys = key_order if key_order else sorted(payload.keys())

    data_str = ""
    for k in keys:
        data_str += str(payload.get(k, ""))

    # Create signature
    msg = api_key + data_str

    return hmac.new(passcode.encode(), msg.encode(), hashlib.sha256).hexdigest()
```

> **Note:** Old snippets using `api_key` as a single string parameter are still supported. The engine will automatically pass the first custom data value as `api_key` for backward compatibility.

---

## Files

| File | Description |
|---|---|
| `HashGen.py` | Standalone desktop app (CustomTkinter) |
| `HashGenBurp.py` | Burp Suite extension (Jython) |
| `snippets.json` | Saved algorithm snippets (shared between both tools) |
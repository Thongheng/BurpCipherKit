# CipherKit — Migration Guide
## Module Split + Montoya API

This guide covers two things done together:

1. **Module split** — break `HashGenBurp.py` into `core/` and `ui/` packages
2. **Montoya API** — rewrite from the old Jython/Wiener API (`IBurpExtender`, `ITab`, etc.) to the modern Java Montoya API (`BurpExtension`, `MontoyaApi`, etc.)

These are done together because the Montoya API requires Java, and splitting the code into modules is easier to do in Java from the start than retrofitting a 3000-line Python file.

---

## What Changes and Why

### Old API (current CipherKit)
- Written in **Python (Jython 2.7)**
- Loaded as a `.py` file in Burp Extender
- Relies on `IBurpExtender`, `ITab`, `IMessageEditorTabFactory`, `ISessionHandlingAction`
- All code in one file: `HashGenBurp.py`
- Requires Jython JAR configured in Burp settings

### New API (Montoya)
- Written in **Java** (or Kotlin)
- Loaded as a compiled `.jar` file
- Entry point implements `BurpExtension` and receives a `MontoyaApi` object
- No Jython dependency — works natively in all modern Burp versions
- PortSwigger actively maintains and documents it; old API is deprecated

---

## Interface Mapping — Old → New

| Old (Wiener/Jython) | New (Montoya Java) | Notes |
|---|---|---|
| `IBurpExtender` | `BurpExtension` | Entry point. `registerExtenderCallbacks()` → `initialize(MontoyaApi)` |
| `IBurpExtenderCallbacks` | `MontoyaApi` | Central API object passed to `initialize()` |
| `IExtensionHelpers` | `MontoyaApi.utilities()` | String/byte helpers, URL encoding, etc. |
| `ITab` | `MontoyaApi.userInterface().registerSuiteTab()` | Register a JPanel directly, no interface needed |
| `IMessageEditorTabFactory` | `MontoyaApi.userInterface().registerHttpRequestEditorProvider()` | Returns `ExtensionProvidedHttpRequestEditor` |
| `IMessageEditorTab` | `ExtensionProvidedHttpRequestEditor` | Interface for inline editor tabs |
| `ISessionHandlingAction` | **No direct equivalent** (see note below) | Use `HttpHandler` or `IntruderPayloadProcessor` instead |
| `IContextMenuFactory` | `MontoyaApi.userInterface().registerContextMenuItemsProvider()` | `ContextMenuItemsProvider` interface |
| `callbacks.setExtensionName()` | `api.extension().setName()` | Same purpose |
| `callbacks.registerContextMenuFactory()` | `api.userInterface().registerContextMenuItemsProvider()` | |
| `callbacks.addSuiteTab()` | `api.userInterface().registerSuiteTab()` | |
| `callbacks.getStdout()` / `getStderr()` | `api.logging().logToOutput()` / `logToError()` | |
| `helpers.analyzeRequest()` | `api.utilities().requestUtils()` or parse `HttpRequest` directly | |
| `helpers.bytesToString()` | `httpRequest.bodyToString()` or `new String(bytes)` | Built into request/response objects |
| `helpers.buildHttpMessage()` | `HttpRequest.httpRequest(headers, body)` | |
| `currentRequest.getRequest()` | `requestResponse.request()` | Returns typed `HttpRequest` object |
| `currentRequest.setRequest()` | Return modified request from handler | Handler returns `RequestToBeSentAction` |

> **Note on `ISessionHandlingAction`:** Montoya has no direct replacement. The recommended approach is to register an `HttpHandler` via `api.http().registerHttpHandler()` and filter by tool type (`ToolType.INTRUDER`, `ToolType.REPEATER`). This achieves the same rehash-on-every-request behaviour without needing Session Handling Rules.

---

## Target Folder Structure

```
CipherKit/
├── src/
│   └── main/
│       └── java/
│           └── com/cipherkit/
│               ├── CipherKit.java          ← entry point (implements BurpExtension)
│               ├── core/
│               │   ├── CryptoEngine.java       ← snippet execution
│               │   ├── AesCbcEngine.java        ← AES-CBC built-in
│               │   ├── BodyParser.java          ← parse/serialize JSON, URL-enc, multipart
│               │   ├── SnippetManager.java      ← load/save snippets.json
│               │   ├── CryptoSnippetManager.java
│               │   ├── AppSettingManager.java    ← load/save app_settings.json
│               │   └── SessionRehashHandler.java ← HttpHandler for auto-rehash
│               └── ui/
│                   ├── MainTab.java             ← top-level JTabbedPane
│                   ├── HashTab.java             ← Hash sub-tab
│                   ├── CryptoTab.java           ← Crypto sub-tab
│                   ├── KeyFinderTab.java        ← Key Finder sub-tab
│                   ├── AppSettingTab.java        ← AppSetting sub-tab
│                   ├── SnippetEditorTab.java    ← Hash Editor sub-tab
│                   ├── CryptoEditorTab.java     ← Crypto Editor sub-tab
│                   ├── InlineEditorTab.java     ← implements ExtensionProvidedHttpRequestEditor
│                   └── components/
│                       ├── CustomDataPanel.java
│                       ├── CompactCustomDataPanel.java
│                       └── RoundedBorder.java
├── build.gradle
└── settings.gradle
```

---

## Step-by-Step Migration Plan

### Step 1 — Set up the Java project

Create a Gradle project and add the Montoya API dependency.

**`build.gradle`:**
```groovy
plugins {
    id 'java'
    id 'com.github.johnrengelman.shadow' version '8.1.1'
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly 'net.portswigger.burp.extensions:montoya-api:2026.2'
}

shadowJar {
    archiveClassifier.set('')
}
```

The `shadow` plugin bundles everything into one fat JAR. `compileOnly` means the Montoya API is available at compile time but not packaged (Burp provides it at runtime).

---

### Step 2 — Create the entry point

Replace `class BurpExtender(IBurpExtender, ...)` with:

```java
package com.cipherkit;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.cipherkit.core.*;
import com.cipherkit.ui.MainTab;

public class CipherKit implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CipherKit");

        // Core managers (pass api for file path resolution)
        String dir = api.extension().filename();
        SnippetManager snippets = new SnippetManager(dir + "/snippets.json");
        CryptoSnippetManager cryptoSnippets = new CryptoSnippetManager(dir + "/crypto_snippets.json");
        AppSettingManager appSettings = new AppSettingManager(dir + "/app_settings.json");

        // UI — main tab
        MainTab mainTab = new MainTab(api, snippets, cryptoSnippets, appSettings);
        api.userInterface().registerSuiteTab("CipherKit", mainTab.getPanel());

        // Inline editor tab
        api.userInterface().registerHttpRequestEditorProvider(
            new InlineEditorProvider(api, snippets, cryptoSnippets, appSettings)
        );

        // Context menu
        api.userInterface().registerContextMenuItemsProvider(
            new CipherKitContextMenu(api, mainTab)
        );

        // Auto-rehash HTTP handler (replaces ISessionHandlingAction)
        api.http().registerHttpHandler(
            new SessionRehashHandler(api, appSettings, snippets)
        );

        api.logging().logToOutput("[+] CipherKit loaded");
    }
}
```

---

### Step 3 — Migrate core logic (no API changes needed)

The core classes (`CryptoEngine`, `AesCbcEngine`, `BodyParser`, `SnippetManager`, `CryptoSnippetManager`, `AppSettingManager`) contain **pure Python/Java logic with no Burp API calls**. Move them to Java classes in `core/` with minimal changes:

- Python `dict` → `Map<String, String>`
- Python `json.loads` → `org.json` or `com.google.gson`
- Python `exec()` → **keep using Jython** (embed a `PythonInterpreter` from Jython as a library dependency in your JAR — this lets you keep all existing snippet code working)

**Embedding Jython for snippets:**
```groovy
// build.gradle — add Jython as a bundled dependency
implementation 'org.python:jython-standalone:2.7.3'
```

```java
// CryptoEngine.java
import org.python.util.PythonInterpreter;

public class CryptoEngine {
    public static String executeSnippet(String code, Map<String,String> payload,
                                         String secret, Map<String,String> customData,
                                         List<String> keyOrder) {
        try (PythonInterpreter py = new PythonInterpreter()) {
            py.set("payload", payload);
            py.set("passcode", secret);
            py.set("custom_data", customData);
            py.set("key_order", keyOrder);
            py.exec(code);
            py.exec("_result = generate(payload, passcode, custom_data, key_order)");
            return py.get("_result", String.class);
        }
    }
}
```

This means **all existing snippets.json and crypto_snippets.json files work without any changes**.

---

### Step 4 — Migrate the inline editor tab

Replace `IMessageEditorTab` / `IMessageEditorTabFactory` with `ExtensionProvidedHttpRequestEditor`:

```java
// InlineEditorProvider.java
import burp.api.montoya.ui.editor.extension.*;

public class InlineEditorProvider implements HttpRequestEditorProvider {
    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
        return new InlineEditorTab(api, snippets, cryptoSnippets, appSettings, ctx);
    }
}

// InlineEditorTab.java
public class InlineEditorTab implements ExtensionProvidedHttpRequestEditor {
    private JPanel panel; // same Swing panel as before

    @Override
    public HttpRequest getRequest() {
        // return modified request from bodyArea
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        // populate bodyArea from requestResponse.request().bodyToString()
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return !requestResponse.request().bodyToString().isBlank();
    }

    @Override
    public String caption() { return "CipherKit"; }

    @Override
    public Component uiComponent() { return panel; }

    @Override
    public Selection selectedData() { return null; }

    @Override
    public boolean isModified() { /* compare original vs current */ }
}
```

---

### Step 5 — Migrate Auto-Rehash (replaces ISessionHandlingAction)

In Montoya, register an `HttpHandler` that fires on Intruder/Repeater requests:

```java
// SessionRehashHandler.java
import burp.api.montoya.http.handler.*;
import burp.api.montoya.core.ToolType;

public class SessionRehashHandler implements HttpHandler {

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // Only act on Intruder or Repeater
        if (!request.toolSource().isFromTool(ToolType.INTRUDER, ToolType.REPEATER)) {
            return RequestToBeSentAction.continueWith(request);
        }

        String urlPath = request.path();
        AppSettingMatch match = appSettings.findByUrl(urlPath);
        if (match == null) {
            return RequestToBeSentAction.continueWith(request);
        }

        // Rehash and inject
        String newBody = rehash(request.bodyToString(), request.contentType(), match);
        HttpRequest updated = request.withBody(newBody);
        return RequestToBeSentAction.continueWith(updated);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response); // no-op
    }
}
```

No Session Handling Rules setup required — it fires automatically.

---

### Step 6 — Build and load

```bash
./gradlew shadowJar
# Output: build/libs/CipherKit.jar
```

In Burp: **Extensions → Add → Java → select `CipherKit.jar`**

No Jython JAR needed in Burp settings anymore (it's bundled in the JAR).

---

## Migration Summary

| What | Old | New |
|------|-----|-----|
| Language | Python 2.7 (Jython) | Java 11+ |
| Load format | `.py` file | `.jar` file |
| Entry point | `registerExtenderCallbacks()` | `initialize(MontoyaApi)` |
| Snippet execution | `exec()` in Jython runtime | Embedded `PythonInterpreter` (Jython as library) |
| Snippet files | Unchanged | Unchanged — fully compatible |
| AppSetting files | Unchanged | Unchanged — fully compatible |
| Session rehash | `ISessionHandlingAction` + Session Rules | `HttpHandler` filtering by `ToolType` |
| Inline tab | `IMessageEditorTabFactory` | `HttpRequestEditorProvider` |
| Jython requirement | Required in Burp settings | Bundled in JAR, not needed in Burp |

---

## Effort Estimate

| Step | Effort |
|------|--------|
| Project setup + entry point | 1–2 hours |
| Core logic migration (managers, parsers) | 2–3 hours |
| UI migration (main tab, sub-tabs) | 4–6 hours |
| Inline editor tab migration | 3–4 hours |
| Auto-rehash HttpHandler | 1 hour |
| Testing + debugging | 3–5 hours |
| **Total** | **~2–3 days** |

The UI work is the biggest part because Swing code is verbose in Java compared to Python. The core logic and snippet system are straightforward since the business logic doesn't touch the Burp API.

# Compact Inline AppSetting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the inline AppSetting tab a compact, request-specific counterpart to the main AppSetting tab while keeping full profile management in the main CipherKit tab.

**Architecture:** Add an app-scoped endpoint resolver to `AppSettingManager` so manual inline loading uses the same exact/glob/substring precedence as automatic loading. Update `HashGenEditorTab` to show compact profile, URL, matched-endpoint, sign-order, and dynamic-value controls; remove inline deletion and render a redacted summary. The main extender exposes a small navigation method for the inline “Open Main AppSetting” action.

**Tech Stack:** Python/Jython, Burp Suite extension APIs, Java Swing, Python `unittest`.

## Global Constraints

- Preserve the existing light Burp/Swing visual language and compact spacing.
- Do not expose profile secrets, crypto keys, or IVs in the inline AppSetting view.
- Keep app deletion and full profile editing in the main CipherKit AppSetting tab.
- Use the same resolver precedence for manual and automatic inline loading.

---

### Task 1: Resolve an endpoint within a selected app consistently

**Files:**
- Modify: `core/app_setting_manager.py:106-145`
- Modify: `tests/test_app_setting_manager.py:1-70`

**Interfaces:**
- Produces: `AppSettingManager.find_endpoint_in_app(app_name, url_path) -> (pattern, endpoint)`.
- Consumes: `find_by_url` scoring rules for exact, glob, then substring matches.

- [ ] **Step 1: Write the failing test**

```python
def test_selected_app_uses_most_specific_endpoint_match(self):
    self.manager.app_settings = {
        "ABA Mobile": {
            "endpoints": {
                "/api/v3/*": {"keys_order": "broad"},
                "/api/v3/pay": {"keys_order": "exact"},
            }
        }
    }

    pattern, endpoint = self.manager.find_endpoint_in_app("ABA Mobile", "/api/v3/pay")

    self.assertEqual("/api/v3/pay", pattern)
    self.assertEqual("exact", endpoint["keys_order"])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_app_setting_manager.ResolveForUrlTests.test_selected_app_uses_most_specific_endpoint_match -v`

Expected: FAIL because `find_endpoint_in_app` does not exist.

- [ ] **Step 3: Write the minimal implementation**

```python
def find_endpoint_in_app(self, app_name, url_path):
    app = self.get_app(app_name)
    if not app or not url_path:
        return (None, None)
    candidates = []
    for sequence, (pattern, endpoint) in enumerate(app.get("endpoints", {}).items()):
        if url_path == pattern:
            kind = 3
        elif fnmatch.fnmatch(url_path, pattern):
            kind = 2
        elif pattern in url_path:
            kind = 1
        else:
            continue
        literal_length = len(pattern.replace("*", "").replace("?", ""))
        candidates.append(((kind, literal_length, -sequence), pattern, endpoint))
    if not candidates:
        return (None, None)
    _, pattern, endpoint = max(candidates, key=lambda candidate: candidate[0])
    return (pattern, endpoint)
```

- [ ] **Step 4: Run the targeted test and full suite**

Run: `python3 -m unittest discover -s tests -v`

Expected: PASS with all tests green.

### Task 2: Compact the inline AppSetting view and hide sensitive configuration

**Files:**
- Modify: `ui/editor_tab.py:213-299, 521-602, 1156-1241`
- Modify: `HashGenBurp.py:1583-1609`

**Interfaces:**
- Consumes: `find_endpoint_in_app` from Task 1.
- Produces: compact inline controls named `_inlineMatchedEndpointField` and `_inlineOpenMainSettingsBtn`.
- Produces: `BurpExtender.show_main_app_setting()` to select the main AppSetting suite tab.

- [ ] **Step 1: Write the failing resolver test before UI integration**

```python
def test_selected_app_returns_no_endpoint_for_unmatched_url(self):
    pattern, endpoint = self.manager.find_endpoint_in_app("ABA Mobile", "/unmatched")
    self.assertIsNone(pattern)
    self.assertIsNone(endpoint)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_app_setting_manager.ResolveForUrlTests.test_selected_app_returns_no_endpoint_for_unmatched_url -v`

Expected: FAIL until Task 1’s resolver handles unmatched paths.

- [ ] **Step 3: Implement the compact UI**

```python
# Inline rows: App Setting + Load + Open Main AppSetting; Current URL;
# Matched Endpoint (read-only); Sign Order + Save Endpoint; Update Value + Apply.
# The summary only shows profile, endpoint, sign order, and custom-data keys.
# It must not render secret, crypto key, or IV values.
```

- [ ] **Step 4: Run automated tests and perform the Burp smoke check**

Run: `python3 -m unittest discover -s tests -v`

Expected: PASS.

Manual Burp check: load a request matching overlapping patterns, open CipherKit → AppSetting, verify the matched endpoint is the most specific one; verify `Open Main AppSetting` selects the suite tab; verify no secret/key/IV appears in the inline summary.

### Task 3: Verify and commit the focused change

**Files:**
- Modify: `core/app_setting_manager.py`
- Modify: `ui/editor_tab.py`
- Modify: `HashGenBurp.py`
- Modify: `tests/test_app_setting_manager.py`

- [ ] **Step 1: Inspect the focused diff**

Run: `git diff --check && git diff -- core/app_setting_manager.py ui/editor_tab.py HashGenBurp.py tests/test_app_setting_manager.py`

Expected: no whitespace errors and only compact AppSetting behavior changes.

- [ ] **Step 2: Run the complete automated suite**

Run: `python3 -m unittest discover -s tests -v`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add core/app_setting_manager.py ui/editor_tab.py HashGenBurp.py tests/test_app_setting_manager.py docs/superpowers/plans/2026-07-10-compact-inline-appsetting.md
git commit -m "feat: compact inline app settings"
```

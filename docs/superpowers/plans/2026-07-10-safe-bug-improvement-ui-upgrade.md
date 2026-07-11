# Safe Bug Fixes, Improvements, and UI Upgrade Plan

> **For agentic workers:** Preserve the existing Generate → Inject hash flow. Do not add a preview stage or automatic decrypt/encrypt stage to normal hashing.

**Goal:** Fix confirmed correctness bugs and improve the light Burp/Swing UI without changing the existing request-signing flow.

**Architecture:** Keep parsing, profile resolution, and signing APIs stable. Add small pure helpers for shared/endpoint configuration merging and safe multipart delimiter handling, then update callers. Keep UI changes presentation-focused and make Key Finder work off the Swing event thread.

**Tech Stack:** Python/Jython, Java Swing, Burp legacy extension APIs, Python `unittest`.

## Global Constraints

- Preserve the existing Generate → Inject behavior.
- Do not add Preview, atomic decrypt/encrypt/sign pipelines, or automatic flow changes.
- Preserve existing `app_settings.json` and snippet formats with migration-safe changes.
- Keep the existing light Burp/Swing visual style.
- Do not expose secrets, crypto keys, or IVs in inline summaries.

## Phases

1. Correctness: multipart delimiters, custom-data overrides, profile resolver parity, and disabled-tab behavior.
2. Responsiveness: move inline Key Finder DFS off the Swing event thread.
3. UI: compact inline AppSetting plus structured main AppSetting controls, without changing request semantics.
4. Verification: pure-Python regressions, syntax compilation, and a documented manual Burp smoke checklist.

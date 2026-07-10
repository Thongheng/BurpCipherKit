# -*- coding: utf-8 -*-
from __future__ import print_function
import json, os

class AppSettingManager(object):
    """Manages app-level settings stored in a JSON file.
    Each app setting holds shared config + per-endpoint keys_order entries."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.app_settings = {}
        self.load()

    def load(self):
        # Migration logic: if app_settings.json doesn't exist, try to load presets.json
        old_path = self.filepath.replace("app_settings.json", "presets.json")
        source_path = self.filepath
        
        if not os.path.exists(self.filepath) and os.path.exists(old_path):
            source_path = old_path
            print("[CipherKit] Migrating config from %s to %s" % (old_path, self.filepath))
            
        if not os.path.exists(source_path):
            self.app_settings = {}
            self.save()
            return
            
        try:
            with open(source_path, 'r') as f:
                data = json.load(f)
            # Migrate old flat format (has "match_pattern" key at app level)
            migrated = {}
            for name, app in data.items():
                if "match_pattern" in app:
                    pattern = app.get("match_pattern", "")
                    h = app.get("hash", {})
                    c = app.get("crypto", {})
                    migrated[name] = {
                        "algorithm":   h.get("algorithm", ""),
                        "secret":      h.get("secret", ""),
                        "custom_data": h.get("custom_data", {}),
                        "hash_field":  h.get("hash_field", "hash"),
                        "crypto":      c,
                        "endpoints":   {pattern: {"keys_order": h.get("keys_order", "")}} if pattern else {},
                    }
                else:
                    migrated[name] = app
            self.app_settings = migrated
            
            # If we migrated from old file, save to the new location
            if source_path == old_path or migrated != data:
                self.save()
                if source_path == old_path:
                    try:
                        os.rename(old_path, old_path + ".bak")
                        print("[CipherKit] Original presets.json renamed to presets.json.bak")
                    except:
                        pass
        except Exception as e:
            print("[CipherKit] Error loading app settings: %s" % str(e))
            self.app_settings = {}

    def save(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.app_settings, f, indent=2)
            return True
        except Exception as e:
            print("[CipherKit] Error saving app settings: %s" % str(e))
            return False

    def get_all_names(self):
        return list(self.app_settings.keys())

    def get_app(self, name):
        return self.app_settings.get(name)

    def save_app(self, name, data):
        """Save or update app-level config, preserving existing endpoints."""
        if name in self.app_settings:
            existing = self.app_settings[name]
            data["endpoints"] = existing.get("endpoints", {})
            if "default_kf_key" not in data and "default_kf_key" in existing:
                data["default_kf_key"] = existing["default_kf_key"]
        else:
            data.setdefault("endpoints", {})
        self.app_settings[name] = data
        self.save()

    def save_endpoint(self, app_name, url_pattern, keys_order, custom_data=None):
        """Add or update a single endpoint's keys_order and custom_data under an app."""
        if app_name not in self.app_settings:
            self.app_settings[app_name] = {"endpoints": {}}
        self.app_settings[app_name].setdefault("endpoints", {})
        ep_data = {"keys_order": keys_order}
        if custom_data is not None:
            ep_data["custom_data"] = custom_data
        self.app_settings[app_name]["endpoints"][url_pattern] = ep_data
        self.save()

    def delete_app(self, name):
        if name in self.app_settings:
            del self.app_settings[name]
            self.save()

    def find_by_url(self, url_path):
        """Return the most-specific exact, glob, or substring endpoint match."""
        import fnmatch
        candidates = []
        sequence = 0
        for app_name, app in self.app_settings.items():
            for pattern, ep in app.get("endpoints", {}).items():
                if not pattern:
                    continue
                sequence += 1
                if url_path == pattern:
                    match_kind = 3
                elif fnmatch.fnmatch(url_path, pattern):
                    match_kind = 2
                elif pattern in url_path:
                    match_kind = 1
                else:
                    continue
                literal_length = len(pattern.replace("*", "").replace("?", ""))
                score = (match_kind, literal_length, -sequence)
                candidates.append((score, app_name, app, pattern, ep))

        if not candidates:
            return (None, None, None, None)
        best = max(candidates, key=lambda candidate: candidate[0])
        return (best[1], best[2], best[3], best[4])

    def resolve_for_url(self, url_path, default_app_name=None):
        """Resolve an endpoint match, falling back to a configured default app."""
        if url_path:
            matched = self.find_by_url(url_path)
            if matched[1]:
                return matched

        if default_app_name and default_app_name != "(none)":
            app = self.get_app(default_app_name)
            if app:
                return (default_app_name, app, "(default load)", None)

        return (None, None, None, None)


# =============================================================================
# UI Helper: Rounded Border for Swing components

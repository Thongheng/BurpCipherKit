# -*- coding: utf-8 -*-
from __future__ import print_function


def find_key_orders(values, known, max_matches=100, max_visited=10000):
    """Find value concatenation orders without mutating the caller's mapping."""
    keys = list(values.keys())
    normalized = dict((key, str(value)) for key, value in values.items())
    matches = []
    visited = [0]

    def dfs(current, remaining, suffix):
        visited[0] += 1
        if len(matches) >= max_matches or visited[0] >= max_visited:
            return
        if not suffix:
            if current:
                matches.append(tuple(current))
            return
        for key in remaining:
            if visited[0] >= max_visited or len(matches) >= max_matches:
                return
            value = normalized[key]
            if not value or not suffix.startswith(value):
                continue
            next_keys = [candidate for candidate in remaining if candidate != key]
            dfs(current + [key], next_keys, suffix[len(value):])

    dfs([], keys, str(known))
    capped = len(matches) >= max_matches or visited[0] >= max_visited
    return matches, visited[0], capped


def compare_generated_hash(generated_hash, payload, hash_field):
    """Return valid, invalid, missing, or error for a generated hash."""
    generated = str(generated_hash)
    if generated.startswith("Error"):
        return "error"
    if not isinstance(payload, dict) or hash_field not in payload:
        return "missing"
    reference = payload.get(hash_field)
    if reference is None or not str(reference).strip():
        return "missing"
    if str(reference).strip().lower() == generated.strip().lower():
        return "valid"
    return "invalid"


def format_hash_comparison(generated_hash, comparison):
    """Format comparison feedback inside the hash output value."""
    value = strip_hash_comparison(generated_hash)
    if comparison == "valid":
        return value + " (Match)"
    if comparison == "invalid":
        return value + " (Not Match)"
    return value


def strip_hash_comparison(value):
    """Remove comparison feedback when request data changes."""
    text = str(value)
    for suffix in (" (Not Match)", " (Match)"):
        if text.endswith(suffix):
            return text[:-len(suffix)]
    return text


def should_render_hash_output(compare_requested, crypto_output_mode):
    """A comparison must display its generated hash even from Crypto mode."""
    return bool(compare_requested or not crypto_output_mode)

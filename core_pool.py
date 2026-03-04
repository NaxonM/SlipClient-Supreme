"""Resolver pool operations extracted from core.py."""

from __future__ import annotations


def merge_new_with_existing(new_resolvers: list[str], existing: list[str]) -> list[str]:
    """Merge with new resolvers first while preserving stable order and deduping."""
    return list(dict.fromkeys(new_resolvers + existing))


def surviving_resolvers(existing: list[str], is_alive) -> list[str]:
    """Keep resolvers passing the caller-provided liveness predicate."""
    return [ip for ip in existing if is_alive(ip)]

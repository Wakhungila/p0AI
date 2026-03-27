"""
Tests for core/payload_cache.py

Covers:
  - Cache miss returns None
  - Store then hit returns correct payloads
  - Key determinism: tech_stack order does not matter
  - TTL expiry marks entry as stale
  - Invalidate by vuln_type removes only matching entries
  - Invalidate without vuln_type evicts only stale entries
  - store() is idempotent (same key overwrites)
  - Empty payload list is not stored
"""
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.payload_cache import PayloadCache


def _tmp_cache(ttl_hours: int = 72) -> tuple[PayloadCache, str]:
    """Return a PayloadCache backed by a temp DB and the DB path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return PayloadCache(db_path=path, ttl_hours=ttl_hours), path


def test_miss_returns_none():
    cache, path = _tmp_cache()
    try:
        result = cache.hit("xss", ["django", "react"])
        assert result is None, f"Expected None on miss, got {result}"
        print("  PASS test_miss_returns_none")
    finally:
        os.unlink(path)


def test_store_then_hit():
    cache, path = _tmp_cache()
    try:
        payloads = ["<script>alert(1)</script>", "'OR 1=1--"]
        cache.store("xss", ["django"], payloads)
        result = cache.hit("xss", ["django"])
        assert result == payloads, f"Expected {payloads}, got {result}"
        print("  PASS test_store_then_hit")
    finally:
        os.unlink(path)


def test_key_determinism_tech_order():
    """['react','django'] and ['django','react'] must resolve to same cache entry."""
    cache, path = _tmp_cache()
    try:
        payloads = ["payload_a", "payload_b"]
        cache.store("sqli", ["react", "django"], payloads)
        # Look up with reversed order
        result = cache.hit("sqli", ["django", "react"])
        assert result == payloads, \
            f"Key not deterministic across tech_stack ordering. Got {result}"
        print("  PASS test_key_determinism_tech_order")
    finally:
        os.unlink(path)


def test_key_determinism_tech_case():
    """['Django'] and ['django'] must resolve to the same entry."""
    cache, path = _tmp_cache()
    try:
        payloads = ["test_payload"]
        cache.store("lfi", ["Django", "React"], payloads)
        result = cache.hit("lfi", ["react", "django"])
        assert result == payloads, \
            f"Key not deterministic across tech_stack casing. Got {result}"
        print("  PASS test_key_determinism_tech_case")
    finally:
        os.unlink(path)


def test_different_vuln_types_are_independent():
    cache, path = _tmp_cache()
    try:
        xss_payloads = ["<xss>"]
        sqli_payloads = ["' OR 1=1"]
        cache.store("xss", ["nginx"], xss_payloads)
        cache.store("sqli", ["nginx"], sqli_payloads)
        assert cache.hit("xss", ["nginx"]) == xss_payloads
        assert cache.hit("sqli", ["nginx"]) == sqli_payloads
        assert cache.hit("ssrf", ["nginx"]) is None
        print("  PASS test_different_vuln_types_are_independent")
    finally:
        os.unlink(path)


def test_different_tech_stacks_are_independent():
    cache, path = _tmp_cache()
    try:
        django_payloads = ["django_specific"]
        rails_payloads = ["rails_specific"]
        cache.store("xss", ["django"], django_payloads)
        cache.store("xss", ["rails"], rails_payloads)
        assert cache.hit("xss", ["django"]) == django_payloads
        assert cache.hit("xss", ["rails"]) == rails_payloads
        print("  PASS test_different_tech_stacks_are_independent")
    finally:
        os.unlink(path)


def test_ttl_fresh_entry_returns_hit():
    cache, path = _tmp_cache(ttl_hours=1)
    try:
        payloads = ["fresh_payload"]
        cache.store("xss", [], payloads)
        result = cache.hit("xss", [])
        assert result == payloads, f"Fresh entry should hit, got {result}"
        print("  PASS test_ttl_fresh_entry_returns_hit")
    finally:
        os.unlink(path)


def test_ttl_stale_entry_returns_none():
    """Manually backdate a cache entry to simulate TTL expiry."""
    import sqlite3
    cache, path = _tmp_cache(ttl_hours=1)
    try:
        payloads = ["stale_payload"]
        cache.store("xss", [], payloads)
        # Backdate the entry by 2 hours
        two_hours_ago = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        conn = sqlite3.connect(path)
        conn.execute(
            "UPDATE payload_cache SET cached_at = ? WHERE vuln_type = 'xss'",
            (two_hours_ago,)
        )
        conn.commit()
        conn.close()
        result = cache.hit("xss", [])
        assert result is None, \
            f"Stale entry (2h old, TTL=1h) should return None, got {result}"
        print("  PASS test_ttl_stale_entry_returns_none")
    finally:
        os.unlink(path)


def test_store_is_idempotent():
    cache, path = _tmp_cache()
    try:
        cache.store("xss", ["react"], ["v1"])
        cache.store("xss", ["react"], ["v2_updated"])
        result = cache.hit("xss", ["react"])
        assert result == ["v2_updated"], \
            f"store() should overwrite. Expected ['v2_updated'], got {result}"
        print("  PASS test_store_is_idempotent")
    finally:
        os.unlink(path)


def test_empty_payload_list_not_stored():
    cache, path = _tmp_cache()
    try:
        cache.store("xss", ["django"], [])
        result = cache.hit("xss", ["django"])
        assert result is None, \
            f"Empty payload list should not be stored, got {result}"
        print("  PASS test_empty_payload_list_not_stored")
    finally:
        os.unlink(path)


def test_invalidate_by_vuln_type():
    cache, path = _tmp_cache()
    try:
        cache.store("xss",  ["nginx"], ["xss_payload"])
        cache.store("sqli", ["nginx"], ["sqli_payload"])
        deleted = cache.invalidate(vuln_type="xss")
        assert deleted == 1, f"Expected 1 deletion, got {deleted}"
        assert cache.hit("xss", ["nginx"]) is None, "xss entry should be gone"
        assert cache.hit("sqli", ["nginx"]) == ["sqli_payload"], \
            "sqli entry should still exist"
        print("  PASS test_invalidate_by_vuln_type")
    finally:
        os.unlink(path)


def test_invalidate_stale_only():
    """invalidate() with no vuln_type should only remove stale entries."""
    import sqlite3
    cache, path = _tmp_cache(ttl_hours=1)
    try:
        cache.store("xss",  [], ["fresh"])
        cache.store("sqli", [], ["also_fresh"])
        # Backdate sqli entry to make it stale
        two_hours_ago = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        conn = sqlite3.connect(path)
        conn.execute(
            "UPDATE payload_cache SET cached_at = ? WHERE vuln_type = 'sqli'",
            (two_hours_ago,)
        )
        conn.commit()
        conn.close()
        deleted = cache.invalidate()  # no vuln_type → evict stale only
        assert deleted == 1, f"Expected 1 stale deletion, got {deleted}"
        assert cache.hit("xss", []) == ["fresh"], "Fresh xss entry should survive"
        assert cache.hit("sqli", []) is None, "Stale sqli entry should be gone"
        print("  PASS test_invalidate_stale_only")
    finally:
        os.unlink(path)


def test_stats_accuracy():
    import sqlite3
    cache, path = _tmp_cache(ttl_hours=1)
    try:
        cache.store("xss",  [], ["p1"])
        cache.store("sqli", [], ["p2"])
        cache.store("lfi",  [], ["p3"])
        # Backdate one entry to stale
        two_hours_ago = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        conn = sqlite3.connect(path)
        conn.execute(
            "UPDATE payload_cache SET cached_at = ? WHERE vuln_type = 'lfi'",
            (two_hours_ago,)
        )
        conn.commit()
        conn.close()
        stats = cache.stats()
        assert stats["total"] == 3, f"Expected 3 total, got {stats['total']}"
        assert stats["stale"] == 1, f"Expected 1 stale, got {stats['stale']}"
        assert "xss" in stats["by_type"]
        assert "sqli" in stats["by_type"]
        assert "lfi" in stats["by_type"]
        print("  PASS test_stats_accuracy")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    print("\nPayloadCache Tests")
    print("=" * 40)
    test_miss_returns_none()
    test_store_then_hit()
    test_key_determinism_tech_order()
    test_key_determinism_tech_case()
    test_different_vuln_types_are_independent()
    test_different_tech_stacks_are_independent()
    test_ttl_fresh_entry_returns_hit()
    test_ttl_stale_entry_returns_none()
    test_store_is_idempotent()
    test_empty_payload_list_not_stored()
    test_invalidate_by_vuln_type()
    test_invalidate_stale_only()
    test_stats_accuracy()
    print("\nAll PayloadCache tests passed.")

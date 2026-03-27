"""
Tests for core/llm_budget.py

Covers:
  - charge() returns True when under ceiling
  - charge() returns False when at or over ceiling
  - record_cache_hit() increments cache counter only
  - total_calls() counts charged calls only
  - total_cache_hits() counts cache hits only
  - Denied calls do NOT increment calls_made
  - summary() percentages are arithmetically correct
  - Custom ceilings override defaults
  - Default ceilings match 8GB-optimised spec
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.llm_budget import LLMBudget


def test_charge_under_ceiling_returns_true():
    budget = LLMBudget(ceilings={"tester_mutation": 3})
    assert budget.charge("tester_mutation") is True
    assert budget.charge("tester_mutation") is True
    assert budget.charge("tester_mutation") is True
    print("  PASS test_charge_under_ceiling_returns_true")


def test_charge_at_ceiling_returns_false():
    budget = LLMBudget(ceilings={"tester_mutation": 2})
    budget.charge("tester_mutation")
    budget.charge("tester_mutation")
    result = budget.charge("tester_mutation")
    assert result is False, f"Expected False at ceiling, got {result}"
    print("  PASS test_charge_at_ceiling_returns_false")


def test_denied_calls_not_counted_as_made():
    budget = LLMBudget(ceilings={"tester_mutation": 1})
    budget.charge("tester_mutation")   # allowed — count=1
    budget.charge("tester_mutation")   # denied
    budget.charge("tester_mutation")   # denied
    assert budget.total_calls() == 1, \
        f"Only 1 call should have been made, got {budget.total_calls()}"
    print("  PASS test_denied_calls_not_counted_as_made")


def test_cache_hits_independent_of_call_count():
    budget = LLMBudget()
    budget.charge("tester_mutation")
    budget.record_cache_hit("tester_mutation")
    budget.record_cache_hit("tester_mutation")
    assert budget.total_calls() == 1
    assert budget.total_cache_hits() == 2
    print("  PASS test_cache_hits_independent_of_call_count")


def test_unknown_key_uses_high_default_ceiling():
    """Unknown keys should have a very high ceiling — not deny by default."""
    budget = LLMBudget()
    for _ in range(20):
        result = budget.charge("some_unknown_key")
        assert result is True, "Unknown keys should default to high ceiling"
    print("  PASS test_unknown_key_uses_high_default_ceiling")


def test_multiple_keys_are_independent():
    budget = LLMBudget(ceilings={"key_a": 1, "key_b": 5})
    assert budget.charge("key_a") is True
    assert budget.charge("key_a") is False   # key_a exhausted
    assert budget.charge("key_b") is True    # key_b still available
    assert budget.charge("key_b") is True
    assert budget.total_calls() == 3  # 1 from key_a + 2 from key_b
    print("  PASS test_multiple_keys_are_independent")


def test_summary_totals_are_correct():
    budget = LLMBudget(ceilings={"mut": 3, "cvss": 2})
    budget.charge("mut")          # made: 1
    budget.charge("mut")          # made: 2
    budget.charge("mut")          # made: 3
    budget.charge("mut")          # denied: 1
    budget.record_cache_hit("mut")  # cache: 1
    budget.charge("cvss")         # made: 4
    budget.charge("cvss")         # made: 5
    budget.charge("cvss")         # denied: 1

    s = budget.summary()
    assert s["llm_calls_made"] == 5,    f"Expected 5 calls made, got {s['llm_calls_made']}"
    assert s["cache_hits"] == 1,        f"Expected 1 cache hit, got {s['cache_hits']}"
    assert s["calls_denied_by_ceiling"] == 2, \
        f"Expected 2 denied, got {s['calls_denied_by_ceiling']}"
    # total = made + cache + denied = 5 + 1 + 2 = 8
    assert s["total_requests"] == 8,    f"Expected 8 total, got {s['total_requests']}"
    # savings = (cache + denied) / total = (1+2)/8 = 0.375 → rounds to 38%
    assert s["llm_savings_pct"] == 38,  f"Expected 38% savings, got {s['llm_savings_pct']}%"
    print("  PASS test_summary_totals_are_correct")


def test_summary_zero_calls():
    """Budget with no activity should not divide by zero."""
    budget = LLMBudget()
    s = budget.summary()
    assert s["llm_calls_made"] == 0
    assert s["llm_savings_pct"] == 0
    print("  PASS test_summary_zero_calls")


def test_default_ceilings_match_8gb_spec():
    """
    Verify that default ceilings match the documented 8GB-optimised values.
    If someone changes the defaults they must update this test deliberately.
    """
    budget = LLMBudget()
    expected = {
        "tester_mutation":  8,
        "tester_business":  1,
        "strategy_score":   1,
        "strategy_plan":    1,
        "debator_cvss":     10,
    }
    for key, expected_ceiling in expected.items():
        actual = budget._ceilings.get(key)
        assert actual == expected_ceiling, \
            f"Ceiling mismatch for '{key}': expected {expected_ceiling}, got {actual}"
    # debator_validate and knowledge_extract should be effectively unlimited
    assert budget._ceilings.get("debator_validate", 0) >= 9999
    assert budget._ceilings.get("knowledge_extract", 0) >= 9999
    print("  PASS test_default_ceilings_match_8gb_spec")


def test_custom_ceilings_override_defaults():
    budget = LLMBudget(ceilings={"tester_mutation": 99, "debator_cvss": 0})
    assert budget._ceilings["tester_mutation"] == 99
    assert budget._ceilings["debator_cvss"] == 0
    # debator_validate should still be the default
    assert budget._ceilings.get("debator_validate", 0) >= 9999
    print("  PASS test_custom_ceilings_override_defaults")


def test_zero_ceiling_always_denies():
    budget = LLMBudget(ceilings={"blocked_op": 0})
    for _ in range(5):
        result = budget.charge("blocked_op")
        assert result is False, "Zero ceiling should always deny"
    assert budget.total_calls() == 0
    print("  PASS test_zero_ceiling_always_denies")


def test_by_key_summary_contains_all_active_keys():
    budget = LLMBudget(ceilings={"alpha": 5, "beta": 3})
    budget.charge("alpha")
    budget.record_cache_hit("beta")
    budget.charge("gamma")   # unknown key, should still appear

    s = budget.summary()
    assert "alpha" in s["by_key"]
    assert "beta" in s["by_key"]
    assert "gamma" in s["by_key"]
    print("  PASS test_by_key_summary_contains_all_active_keys")


if __name__ == "__main__":
    print("\nLLMBudget Tests")
    print("=" * 40)
    test_charge_under_ceiling_returns_true()
    test_charge_at_ceiling_returns_false()
    test_denied_calls_not_counted_as_made()
    test_cache_hits_independent_of_call_count()
    test_unknown_key_uses_high_default_ceiling()
    test_multiple_keys_are_independent()
    test_summary_totals_are_correct()
    test_summary_zero_calls()
    test_default_ceilings_match_8gb_spec()
    test_custom_ceilings_override_defaults()
    test_zero_ceiling_always_denies()
    test_by_key_summary_contains_all_active_keys()
    print("\nAll LLMBudget tests passed.")

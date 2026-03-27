"""
Tests for core/model_lifecycle.py

All tests mock OllamaClient so no Ollama server is needed.

Covers:
  start_preload      — non-blocking, idempotent, replaces completed tasks
  wait_for_model     — hot/warm/cold paths, swap recording, no-op on same model
  transition         — fires background work, respects swap ceiling
  summary            — accurate counts, accumulated wait, warmth tracking
  _record_swap       — correct fields, None from_model handled
"""
import asyncio
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tests.stubs  # noqa: F401


def _mock_ollama(preload_delay: float = 0.0, unload_delay: float = 0.0):
    ollama = MagicMock()

    async def _preload(model):
        if preload_delay > 0:
            await asyncio.sleep(preload_delay)
        return preload_delay

    async def _unload(model):
        if unload_delay > 0:
            await asyncio.sleep(unload_delay)
        return True

    ollama.preload_model = AsyncMock(side_effect=_preload)
    ollama.unload_model = AsyncMock(side_effect=_unload)
    return ollama


def _manager(ollama=None, max_swaps=2, overlap_ok=False):
    from core.model_lifecycle import ModelLifecycleManager
    return ModelLifecycleManager(
        ollama=ollama or _mock_ollama(),
        model_strategy="mistral:7b",
        model_tester="qwen2.5-coder:7b",
        model_debator="llama3.1:8b",
        max_swaps=max_swaps,
        overlap_ok=overlap_ok,
    )


# ─── start_preload ────────────────────────────────────────────────────────────

def test_start_preload_creates_task():
    async def _run():
        mgr = _manager()
        mgr.start_preload("mistral:7b")
        assert "mistral:7b" in mgr._preload_tasks
        assert isinstance(mgr._preload_tasks["mistral:7b"], asyncio.Task)
        await mgr._preload_tasks["mistral:7b"]

    asyncio.run(_run())
    print("  PASS test_start_preload_creates_task")


def test_start_preload_idempotent_while_running():
    async def _run():
        ollama = _mock_ollama(preload_delay=0.05)
        mgr = _manager(ollama)
        mgr.start_preload("mistral:7b")
        task_a = mgr._preload_tasks["mistral:7b"]
        mgr.start_preload("mistral:7b")   # second call while loading
        task_b = mgr._preload_tasks["mistral:7b"]
        assert task_a is task_b
        await task_a

    asyncio.run(_run())
    print("  PASS test_start_preload_idempotent_while_running")


def test_start_preload_replaces_completed_task():
    async def _run():
        mgr = _manager()
        mgr.start_preload("mistral:7b")
        task_a = mgr._preload_tasks["mistral:7b"]
        await task_a
        mgr.start_preload("mistral:7b")   # after completion
        task_b = mgr._preload_tasks.get("mistral:7b")
        assert task_b is not None
        await asyncio.sleep(0)

    asyncio.run(_run())
    print("  PASS test_start_preload_replaces_completed_task")


# ─── wait_for_model ───────────────────────────────────────────────────────────

def test_wait_hot_path_returns_zero():
    async def _run():
        mgr = _manager()
        mgr.start_preload("mistral:7b")
        await mgr._preload_tasks["mistral:7b"]   # preload done
        wait = await mgr.wait_for_model("mistral:7b")
        assert wait == 0.0
        assert mgr._current_model == "mistral:7b"

    asyncio.run(_run())
    print("  PASS test_wait_hot_path_returns_zero")


def test_wait_cold_path_calls_preload():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")   # no preload started
        mgr._ollama.preload_model.assert_called_once_with("mistral:7b")
        assert mgr._current_model == "mistral:7b"
        assert mgr._swap_count == 1

    asyncio.run(_run())
    print("  PASS test_wait_cold_path_calls_preload")


def test_wait_records_swap_on_new_model():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")
        assert mgr._swap_count == 1
        assert mgr._swap_log[0]["to"] == "mistral:7b"
        assert mgr._swap_log[0]["from"] == "(none)"

    asyncio.run(_run())
    print("  PASS test_wait_records_swap_on_new_model")


def test_wait_same_model_no_extra_swap():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")
        count = mgr._swap_count
        await mgr.wait_for_model("mistral:7b")   # already current
        assert mgr._swap_count == count

    asyncio.run(_run())
    print("  PASS test_wait_same_model_no_extra_swap")


def test_wait_warm_path_blocks_until_loaded():
    async def _run():
        ollama = _mock_ollama(preload_delay=0.05)
        mgr = _manager(ollama)
        mgr.start_preload("mistral:7b")
        t0 = time.monotonic()
        await mgr.wait_for_model("mistral:7b")
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.04, f"Should have waited for loading, elapsed={elapsed:.3f}s"

    asyncio.run(_run())
    print("  PASS test_wait_warm_path_blocks_until_loaded")


def test_wait_marks_was_warm_false_on_cold():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")
        assert mgr._swap_log[0]["was_warm"] is False

    asyncio.run(_run())
    print("  PASS test_wait_marks_was_warm_false_on_cold")


# ─── transition ───────────────────────────────────────────────────────────────

def test_transition_triggers_work_below_ceiling():
    async def _run():
        ollama = _mock_ollama()
        mgr = _manager(ollama, max_swaps=2)
        mgr._current_model = "mistral:7b"

        await mgr.transition("mistral:7b", "qwen2.5-coder:7b")
        await asyncio.sleep(0.02)   # let background tasks start

        called_unload = ollama.unload_model.called
        has_preload_task = "qwen2.5-coder:7b" in mgr._preload_tasks
        assert called_unload or has_preload_task, \
            "transition() should fire unload or preload"

    asyncio.run(_run())
    print("  PASS test_transition_triggers_work_below_ceiling")


def test_transition_noop_at_ceiling():
    async def _run():
        ollama = _mock_ollama()
        mgr = _manager(ollama, max_swaps=1)
        mgr._swap_count = 1   # at ceiling

        await mgr.transition("mistral:7b", "qwen2.5-coder:7b")
        await asyncio.sleep(0.02)

        assert not ollama.unload_model.called, \
            "Should not unload when swap ceiling is reached"
        assert "qwen2.5-coder:7b" not in mgr._preload_tasks, \
            "Should not create preload task when ceiling is reached"

    asyncio.run(_run())
    print("  PASS test_transition_noop_at_ceiling")


def test_transition_overlap_fires_concurrent_tasks():
    async def _run():
        ollama = _mock_ollama()
        mgr = _manager(ollama, overlap_ok=True)
        mgr._current_model = "mistral:7b"

        await mgr.transition("mistral:7b", "qwen2.5-coder:7b")
        await asyncio.sleep(0.02)

        # In overlap mode: unload fires immediately, preload task created
        assert ollama.unload_model.called or "qwen2.5-coder:7b" in mgr._preload_tasks

    asyncio.run(_run())
    print("  PASS test_transition_overlap_fires_concurrent_tasks")


# ─── summary ─────────────────────────────────────────────────────────────────

def test_summary_swap_count():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")
        await mgr.wait_for_model("qwen2.5-coder:7b")
        s = mgr.summary()
        assert s["swap_count"] == 2
        assert s["max_swaps"] == 2
        assert len(s["swaps"]) == 2

    asyncio.run(_run())
    print("  PASS test_summary_swap_count")


def test_summary_total_wait_accumulates():
    async def _run():
        ollama = _mock_ollama(preload_delay=0.05)
        mgr = _manager(ollama)
        await mgr.wait_for_model("mistral:7b")
        s = mgr.summary()
        assert s["total_swap_wait_s"] >= 0.04

    asyncio.run(_run())
    print("  PASS test_summary_total_wait_accumulates")


def test_summary_swaps_were_warm_all_hot():
    async def _run():
        mgr = _manager()
        mgr.start_preload("mistral:7b")
        await mgr._preload_tasks["mistral:7b"]
        await mgr.wait_for_model("mistral:7b")
        assert mgr.summary()["swaps_were_warm"] is True

    asyncio.run(_run())
    print("  PASS test_summary_swaps_were_warm_all_hot")


def test_summary_swaps_were_warm_false_on_cold():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")   # cold
        assert mgr.summary()["swaps_were_warm"] is False

    asyncio.run(_run())
    print("  PASS test_summary_swaps_were_warm_false_on_cold")


def test_log_summary_does_not_raise():
    async def _run():
        mgr = _manager()
        await mgr.wait_for_model("mistral:7b")
        mgr.log_summary()   # should not raise

    asyncio.run(_run())
    print("  PASS test_log_summary_does_not_raise")


def test_log_summary_zero_swaps_does_not_raise():
    async def _run():
        mgr = _manager()
        mgr.log_summary()

    asyncio.run(_run())
    print("  PASS test_log_summary_zero_swaps_does_not_raise")


# ─── _record_swap ────────────────────────────────────────────────────────────

def test_record_swap_fields():
    async def _run():
        mgr = _manager()
        mgr._record_swap("mistral:7b", "qwen2.5-coder:7b", 1.23, was_warm=True)
        e = mgr._swap_log[0]
        assert e["from"] == "mistral:7b"
        assert e["to"] == "qwen2.5-coder:7b"
        assert e["wait_s"] == 1.23
        assert e["was_warm"] is True
        assert e["swap_n"] == 1

    asyncio.run(_run())
    print("  PASS test_record_swap_fields")


def test_record_swap_none_from_becomes_none_string():
    async def _run():
        mgr = _manager()
        mgr._record_swap(None, "mistral:7b", 0.5, was_warm=False)
        assert mgr._swap_log[0]["from"] == "(none)"

    asyncio.run(_run())
    print("  PASS test_record_swap_none_from_becomes_none_string")


if __name__ == "__main__":
    print("\nModelLifecycleManager Tests")
    print("=" * 40)
    test_start_preload_creates_task()
    test_start_preload_idempotent_while_running()
    test_start_preload_replaces_completed_task()
    test_wait_hot_path_returns_zero()
    test_wait_cold_path_calls_preload()
    test_wait_records_swap_on_new_model()
    test_wait_same_model_no_extra_swap()
    test_wait_warm_path_blocks_until_loaded()
    test_wait_marks_was_warm_false_on_cold()
    test_transition_triggers_work_below_ceiling()
    test_transition_noop_at_ceiling()
    test_transition_overlap_fires_concurrent_tasks()
    test_summary_swap_count()
    test_summary_total_wait_accumulates()
    test_summary_swaps_were_warm_all_hot()
    test_summary_swaps_were_warm_false_on_cold()
    test_log_summary_does_not_raise()
    test_log_summary_zero_swaps_does_not_raise()
    test_record_swap_fields()
    test_record_swap_none_from_becomes_none_string()
    print("\nAll ModelLifecycleManager tests passed.")

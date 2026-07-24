"""Tests for TargetTester batch execution: ordering + completeness.

Uses a TargetTester instance built without __init__ (no real SDK clients) and a
stubbed ``test_attack``, so these run offline with no credentials.
"""

import threading
import time

from target_tester import TargetTester


def _bare_tester():
    tt = object.__new__(TargetTester)
    tt._print_lock = threading.Lock()
    return tt


def _stub_attack(delay_jitter=0.0):
    def _fn(attack, target, system_prompt=None, auto_judge=True, quiet=False):
        if delay_jitter:
            # Deterministic-ish varied delay by technique index, no RNG.
            idx = int(attack["technique_id"][1:])
            time.sleep((idx % 5) * delay_jitter)
        return {"technique_id": attack["technique_id"], "target": target, "success": False}
    return _fn


def test_parallel_preserves_submission_order():
    tt = _bare_tester()
    tt.test_attack = _stub_attack(delay_jitter=0.005)
    tasks = [({"technique_id": f"T{i}"}, "claude") for i in range(30)]

    results = tt._run_batch_parallel(tasks, None, True, max_workers=8)

    assert len(results) == 30
    assert [r["technique_id"] for r in results] == [f"T{i}" for i in range(30)]


def test_parallel_reports_errors_as_entries_not_exceptions():
    tt = _bare_tester()

    def boom(attack, target, system_prompt=None, auto_judge=True, quiet=False):
        raise RuntimeError("simulated failure")

    tt.test_attack = boom
    tasks = [({"technique_id": "T0"}, "claude")]
    # Single task routes through sequential; force parallel with 2+ tasks.
    tasks = [({"technique_id": "T0"}, "claude"), ({"technique_id": "T1"}, "claude")]

    results = tt._run_batch_parallel(tasks, None, True, max_workers=2)

    assert len(results) == 2
    assert all("error" in r for r in results)


def test_sequential_matches_task_order():
    tt = _bare_tester()
    tt.test_attack = _stub_attack()
    tasks = [({"technique_id": f"T{i}"}, "claude") for i in range(5)]

    results = tt._run_batch_sequential(tasks, None, True)

    assert [r["technique_id"] for r in results] == [f"T{i}" for i in range(5)]

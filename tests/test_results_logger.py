"""Tests for ResultsLogger: thread-safety, atomic writes, corrupt recovery."""

import json
import threading

from results_logger import ResultsLogger

ATTACK = {
    "technique_id": "PI-001",
    "technique_name": "Direct Instruction Override",
    "category": "prompt_injection",
    "severity": "high",
    "generated_prompt": "test prompt",
}


def _logger_at(tmp_path):
    lg = ResultsLogger()
    lg.log_file = str(tmp_path / "attack_log.json")
    lg.results = []
    return lg


def test_impact_scoring(tmp_path):
    lg = _logger_at(tmp_path)
    hit = lg.log_result(ATTACK, "claude", "sure, here...", success=True, notes="")
    miss = lg.log_result(ATTACK, "claude", "I can't help.", success=False, notes="")
    assert hit["impact_score"] == 75  # high severity weight (3) * 25
    assert miss["impact_score"] == 0


def test_concurrent_writes_are_lossless_and_unique(tmp_path):
    lg = _logger_at(tmp_path)

    def worker(n):
        lg.log_result(ATTACK, "claude", f"resp{n}", success=(n % 2 == 0), notes="")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with open(lg.log_file, encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) == 50
    assert sorted(e["id"] for e in data) == list(range(1, 51))


def test_atomic_write_produces_valid_json(tmp_path):
    lg = _logger_at(tmp_path)
    lg.log_result(ATTACK, "claude", "x", success=True, notes="")
    # No leftover temp file, and the log parses.
    assert not (tmp_path / "attack_log.json.tmp").exists()
    with open(lg.log_file, encoding="utf-8") as f:
        assert isinstance(json.load(f), list)


def test_corrupt_log_is_quarantined_not_fatal(tmp_path):
    log_path = tmp_path / "attack_log.json"
    log_path.write_text("{ this is not valid json", encoding="utf-8")

    lg = ResultsLogger()
    lg.log_file = str(log_path)
    recovered = lg._load_existing()  # must not raise

    assert recovered == []
    assert (tmp_path / "attack_log.json.corrupt").exists()


def test_summary_breakdowns(tmp_path):
    lg = _logger_at(tmp_path)
    lg.log_result(ATTACK, "claude", "sure", success=True, notes="")
    lg.log_result(ATTACK, "azure-openai", "no", success=False, notes="")
    summary = lg.get_summary()
    assert summary["total_attacks"] == 2
    assert summary["successful_attacks"] == 1
    assert summary["by_target"]["claude"]["hits"] == 1

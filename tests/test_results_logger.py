"""Tests for ResultsLogger: thread-safety, atomic JSONL writes, corrupt recovery."""

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
    lg.log_file = str(tmp_path / "attack_log.jsonl")
    lg.results = []
    return lg


def _read(lg):
    """Read the log back through the logger's own JSONL parser."""
    return ResultsLogger._read_jsonl(lg.log_file)


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

    data = _read(lg)
    assert len(data) == 50
    assert sorted(e["id"] for e in data) == list(range(1, 51))


def test_atomic_write_produces_valid_jsonl(tmp_path):
    lg = _logger_at(tmp_path)
    lg.log_result(ATTACK, "claude", "x", success=True, notes="")
    # No leftover temp file, and every line parses as JSON.
    assert not (tmp_path / "attack_log.jsonl.tmp").exists()
    data = _read(lg)
    assert isinstance(data, list) and len(data) == 1


def test_roundtrip_reload(tmp_path):
    lg = _logger_at(tmp_path)
    lg.log_result(ATTACK, "claude", "x", success=True, notes="")
    lg.log_result(ATTACK, "bedrock", "y", success=False, notes="")
    # A fresh logger pointed at the same file must see both records.
    lg2 = ResultsLogger()
    lg2.log_file = lg.log_file
    assert len(lg2._load_existing()) == 2


def test_corrupt_log_is_quarantined_not_fatal(tmp_path):
    log_path = tmp_path / "attack_log.jsonl"
    log_path.write_text("{ this is not valid json", encoding="utf-8")

    lg = ResultsLogger()
    lg.log_file = str(log_path)
    recovered = lg._load_existing()  # must not raise

    assert recovered == []
    assert (tmp_path / "attack_log.jsonl.corrupt").exists()


def test_summary_breakdowns(tmp_path):
    lg = _logger_at(tmp_path)
    lg.log_result(ATTACK, "claude", "sure", success=True, notes="")
    lg.log_result(ATTACK, "azure-openai", "no", success=False, notes="")
    summary = lg.get_summary()
    assert summary["total_attacks"] == 2
    assert summary["successful_attacks"] == 1
    assert summary["by_target"]["claude"]["hits"] == 1

import json
from pathlib import Path

TARGET_TECHNIQUES = {"OM-002", "OM-003"}

log_path = Path(__file__).parent / "results" / "attack_log.jsonl"
matches = []
with log_path.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("technique_id") in TARGET_TECHNIQUES and "no content" in record.get("notes", ""):
            matches.append(record)

for tech in sorted(TARGET_TECHNIQUES):
    sample = [m for m in matches if m["technique_id"] == tech]
    print(f"\n=== {tech}: {len(sample)} still failing ===")
    if sample:
        print(json.dumps(sample[-1], indent=2))
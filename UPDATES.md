# Red Team Attack Simulator — Upgrade Log

A comprehensive record of the enterprise hardening and feature work applied to
the simulator. Changes are grouped into five phases, from critical bug fixes
through modern AI-security tooling. Every phase ends green: the project compiles,
all modules import, and the full test suite passes.

**At a glance**

| Metric | Before | After |
|---|---|---|
| Runnable out of the box | ❌ (retired model + import crash) | ✅ |
| Automated tests | 0 | **52** |
| New modules | — | 6 (`utils`, `clients`, `recon`, `verification`, `remediation`, `tests/`) |
| Framework alignment | none | OWASP LLM Top 10 (2025) + MITRE ATLAS on every technique |
| Concurrency | sequential | bounded-parallel, thread-safe |
| CI | scan only | test gate → scan, self-verifying |
| Docs | 1 automation doc | README, LICENSE, `.env.example`, this log |

---

## Phase 1 — Critical Bug Fixes & Configuration Layer

The project was **not runnable** before this phase. Two showstoppers plus several
correctness bugs were fixed, and a real configuration layer was introduced.

### 🔴 Critical fixes

| # | Bug | Impact | Fix |
|---|---|---|---|
| 1 | Every Claude call used `claude-sonnet-4-20250514`, which **retired 2026-06-15** | All Claude target tests + both judges returned 404 — the judging pipeline was dead | Centralized, current, env-overridable models (`JUDGE_MODEL`, `CLAUDE_TARGET_MODEL`) |
| 2 | `import boto3` at module top in `target_tester.py` | boto3 isn't installed → `import target_tester` (and `main.py`) crashed on startup for *all* users | Made Bedrock a **lazy import** — optional dependency |
| 3 | `boto3` and `httpx` imported but absent from `requirements.txt` | Clean `pip install` → `ImportError` | Added both to `requirements.txt` |
| 4 | CI runner counted `r.get("fully_successful")` | Wrong key — chain success count was **always 0** | Corrected to `chain_success` |
| 5 | Connection test treated `"[ERROR] …"` strings as success (truthy) | Reported "Connected" even when a target errored | Inspect for error markers before passing |

### 🟠 Robustness & consistency

- **Fragile judge JSON parsing** (`raw.split("\n",1)[1]…`) replaced with a
  balanced-brace scanner (`utils.extract_json_object`) that survives code fences,
  preambles, trailing prose, and braces inside strings.
- **Inconsistent target menus** in `main.py` reconciled with
  `TargetTester.SUPPORTED_TARGETS`; the multi-turn selector scoped to the two
  targets it actually supports (Azure/Claude) — the old menu offered ARIA/Firewall
  which would raise `ValueError`.
- **`get_chain` null-guard** added to prevent an AttributeError on an unknown ID.
- **Startup validation**: `_preflight_check()` warns about missing configuration
  before the menu loop instead of failing cryptically mid-run.

### New: `config.py` as single source of truth

- Centralized all model IDs and tunables, each env-overridable.
- `validate(capabilities, strict)` / `missing_env(capability)` — fail-fast config
  checks with actionable messages.

### New: `utils.py`

- `extract_json_object()` — robust LLM-JSON extraction.
- `log()` — diagnostics helper (later upgraded to structured logging).

---

## Phase 2 — Concurrency, Logging & Cross-Platform Robustness

### Thread-safe, atomic result logging — `results_logger.py`

- **`threading.Lock`** around every mutation + write (safe under parallel batches).
- **Atomic writes** (temp file + `os.replace`) — a crash mid-write can't corrupt
  `attack_log.json`.
- **Corrupt-file recovery** — a malformed log is quarantined to `.corrupt` and the
  run continues instead of dying on `JSONDecodeError`.

### Parallelized batch testing — `target_tester.py`

- `test_batch` runs with **bounded concurrency** (`MAX_WORKERS`, default 4) —
  bounded workers + SDK 429 backoff *are* the rate-limit control.
- **Results stay in submission order** even though tasks finish out of order; a
  monotonic progress line prints per completion under a lock (no interleaving).
- `quiet` flag added to `test_attack` so parallel workers don't smear output.
- `max_workers=1` preserves the original verbose, sequential behavior.

### Structured logging — `utils.py`

- Real `logging` config on a `redteam` logger → **stderr** (never corrupts piped
  TUI output or generated JSON on stdout). Level via `REDTEAM_LOG_LEVEL` /
  `REDTEAM_DEBUG`.

### 🔴 Cross-platform output crash (found by the stress test)

- The TUI prints `→`, box-drawing, and emoji. On Windows, **any non-interactive
  run** (CI, piped output, redirect to file) used cp1252 and threw
  `UnicodeEncodeError` on the first such character — CI would die before running a
  single attack. Fixed by forcing **UTF-8** on stdout/stderr at import
  (`utils._force_utf8_streams`, `errors="replace"` as a safety net).

---

## Phase 3 — AI-Security Standards, Client Factory, Tests & Docs

### Framework alignment — `attack_taxonomy.py`

The single biggest credibility upgrade for an AI-security tool.

- Every one of the **15 techniques** now carries:
  - an **OWASP Top 10 for LLM Applications (2025)** category (`LLM01:2025`…),
  - one or more **MITRE ATLAS** technique IDs (`AML.T0051`, sub-techniques, …).
- `framework_coverage()` → NIST AI RMF-style coverage report (6/10 OWASP
  categories, 8 ATLAS techniques exercised).
- New lookups: `get_techniques_by_owasp`, `get_techniques_by_atlas`.
- The taxonomy browser (menu 9) surfaces mappings + a live coverage summary.

### SDK client factory — `clients.py`

- One place that constructs every provider client with **consistent retry
  (`MAX_RETRIES`) and timeout (`REQUEST_TIMEOUT`)** policy — the previously *dead*
  `MAX_RETRIES` config is now honored; Bedrock gets a `botocore` retry config too.
- All five engines refactored to use it; duplicated client construction removed.
- Along the way: cleaned dead imports across five modules and fixed a **factually
  wrong docstring** (`generate_aar` claimed Claude, used Azure) + removed a dead
  unused client.

### Test suite — `tests/` (+ `pyproject.toml`, `requirements-dev.txt`)

- Codified every invariant so it can't silently regress. Offline, no credentials.

### Documentation

- **`README.md`** — overview, capabilities, framework-alignment table, architecture
  map, quick-start, CI usage, config reference, responsible-use section.
- **`.env.example`** — fully documented config template (no secrets).
- **`LICENSE`** (MIT) + a prominent **⚠️ Authorized Use Only disclaimer** (essential
  for an offensive-security tool).
- **`.gitignore`** — ignore `.pytest_cache/`.

---

## Phase 4 — AI Pentest Capabilities (Shannon / Xalgorix / Strix)

Capabilities inspired by leading open-source AI pentest projects, adapted to
LLM-application red teaming. Each has a **deterministic, offline-testable core**
plus an **LLM-enhanced path**.

### 🧠 White-box recon — `recon.py` (Shannon-style)

- Reads a target's "source" (system prompt / app config / tool definitions),
  **maps its LLM attack surface**, and recommends the specific taxonomy techniques
  most likely to succeed — targeted engagements instead of blind sweeps.
- Heuristic engine detects: tool/function use, system-prompt secrecy, persona
  surfaces, untrusted-input/RAG, secrets-in-context, output rendering, privileged
  modes; flags risks (e.g. secrets embedded in the prompt).
- Optional Claude deep-read (`analyze_with_llm`) with automatic heuristic fallback.

### 🔬 Verification engine — `verification.py` (Xalgorix-style)

- An **independent adversarial panel** re-checks each *claimed* success with three
  distinct skeptical lenses and **downgrades false positives** — directly attacking
  LLM-judge noise.
- Deterministic majority-vote aggregation; verifier is injectable for testing.

### 🛡️ Actionable remediation — `remediation.py` (Strix-style)

- Findings roll up into **OWASP-keyed mitigation guidance** with concrete controls
  and framework references — reports say *how to fix it*, not just pass/fail.

### Combined pipeline & surfacing

- **Menu 16 — Targeted Engagement**: `recon → generate → attack → verify → remediate`,
  end to end.
- New CLI options **15–18** (recon, engagement, verify, remediation report).
- **HTML dashboard** gains a *Framework Coverage & Remediation* section (OWASP +
  MITRE ATLAS chips + fix guidance).
- **JSON report + CI summary** embed `framework_coverage` and `remediation`.

### CI hardening — `.github/workflows/automated-redteam.yml`

- New offline **`test` job** runs `pytest`; the credentialed **`red-team-scan`
  job `needs: test`** — no API spend if tests fail.
- Fixed the dependency install (was missing `httpx`, which would crash the import
  in CI) to use `requirements.txt` / `requirements-dev.txt`.

---

## Phase 5 — Self-Verifying CI Runs

### `--verify` — `automated_run.py`

- Re-verifies **this run's** successful findings with the adversarial panel and
  **gates critical alerting + remediation on verified findings only** — a judge
  false positive can no longer trip the critical alert or page anyone.
- Single-shot modes (`full`/`category`/`quick`) now return their per-test results
  to feed the verifier; `chains` mode is conversation-scored and cleanly skipped.
- Backward compatible: without `--verify`, critical count comes from
  `logger.get_critical_hits()` exactly as before.

### Cost controls

- **`--verify-judges N`** — votes per finding (default 3).
- **`--verify-threshold {all,medium,high,critical}`** — only verify findings at/above
  a severity; lower-severity hits are trusted without spending verifier calls.

### Workflow

- New `verify` dispatch input (**default `true`**) — **scheduled scans self-filter
  false positives** by default; a manual run can disable it.

---

## Phase 6 — Current-Run Summary & Dashboard Crash Fixes

Two defects that didn't lose data (the raw log always had everything) but shouldn't
ship: the run summary reflected a stale aggregate, and the inline dashboard call
crashed.

### 🔴 Summary reflected a stale aggregate, missed bedrock targets

- `generate_run_summary` called `logger.get_summary()`, which summarized the
  logger's in-memory results **loaded at process start** — i.e. the state *before*
  the run. New entries (including `bedrock` / `bedrock-guardrails` targets) were
  written to disk but never reflected in the summary.
- **Fix**: snapshot the log size before the run; afterward, re-read the log and take
  `entries[pre_run_count:]` as **exactly this run's contribution** (mode-agnostic —
  works for single-shot and chains). The summary, critical count, remediation, and
  verification now all describe the current run. `get_summary`/`get_critical_hits`
  gained an optional subset argument and were made robust to missing keys. The run
  metadata now also lists the exact `targets` exercised.

### 🔴 Dashboard argparse crash on inline generation

- `automated_run.py` called `generate_dashboard.main()`, which runs
  `argparse.parse_args()` on `sys.argv` — but `sys.argv` held *automated_run's*
  flags (`--mode`, `--verify`, …), so argparse aborted with
  `SystemExit: unrecognized arguments`. `except Exception` doesn't catch
  `SystemExit`, so it propagated.
- **Fix**: extracted `build_dashboard(input_path, output_dir)` — a plain callable
  that takes explicit paths and never touches `sys.argv`. `main()` still wraps it
  for CLI use; `automated_run.py` now calls `build_dashboard(LOG_FILE, "docs")`
  directly. No argv collision, no crash.

### Tests added

- `test_summary_reflects_current_run_not_stale_aggregate` — summary shows only the
  current run's targets (bedrock/bedrock-guardrails), not preloaded history.
- `test_no_verify_counts_critical_from_this_run` — critical count from this run.
- `test_dashboard.py` — `build_dashboard` runs in-process with a hostile `sys.argv`
  and on an empty log without crashing.

---

## Reference

### New files

| File | Purpose |
|---|---|
| `config.py` (rewritten) | Central config + validation |
| `clients.py` | SDK client factory (retry/timeout) |
| `utils.py` | JSON extraction, structured logging, UTF-8 output |
| `recon.py` | White-box attack-surface analysis |
| `verification.py` | Adversarial false-positive verification |
| `remediation.py` | OWASP-keyed mitigation guidance |
| `tests/` (9 files) | 52 tests |
| `README.md`, `LICENSE`, `.env.example` | Project documentation |
| `pyproject.toml`, `requirements-dev.txt` | Test config + dev deps |
| `UPDATES.md` | This log |

### New configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `CLAUDE_TARGET_MODEL` | `claude-sonnet-4-5` | Model under test for the `claude` target |
| `JUDGE_MODEL` | `claude-opus-4-8` | Model that scores attack success |
| `MAX_WORKERS` | `4` | Concurrent tests per batch |
| `MAX_RETRIES` | `3` | SDK auto-retry attempts (now honored) |
| `REQUEST_TIMEOUT` | `60` | Per-request timeout (seconds) |
| `REDTEAM_LOG_LEVEL` | `WARNING` | Diagnostic verbosity |
| `REDTEAM_DEBUG` | — | Shorthand for `DEBUG` level |

### New CLI flags — `automated_run.py`

| Flag | Purpose |
|---|---|
| `--verify` | Re-verify findings; gate critical alerts on verified only |
| `--verify-judges N` | Votes per finding (default 3) |
| `--verify-threshold {all,medium,high,critical}` | Severity floor for verification |

### New interactive menu options — `main.py`

| Option | Feature |
|---|---|
| 15 | White-Box Recon (Shannon) |
| 16 | Targeted Engagement (recon → attack → verify → remediate) |
| 17 | Verify Findings (Xalgorix panel) |
| 18 | Remediation Report (Strix) |

### Test coverage (52 tests)

| Suite | Focus |
|---|---|
| `test_utils.py` | Robust JSON extraction (10 cases) |
| `test_results_logger.py` | Concurrency, atomic write, corrupt recovery |
| `test_batch_ordering.py` | Parallel ordering + error handling |
| `test_config.py` | Config validation |
| `test_taxonomy.py` | Framework-mapping integrity |
| `test_recon.py` | White-box surface heuristics |
| `test_verification.py` | Vote aggregation, panel, severity threshold |
| `test_remediation.py` | Mitigation grouping |
| `test_automated_verify.py` | `--verify` critical gating |

### Provider routing (billing awareness)

| Stage | Provider | Default model |
|---|---|---|
| Attack generation | Azure OpenAI | `gpt-4o` |
| Target under test | Amazon Bedrock (or others) | `amazon.nova-lite-v1:0` |
| Judge / Verifier | first-party Anthropic API | `claude-opus-4-8` |

> Judge + verifier dominate cost and run on the first-party Anthropic API (not
> Bedrock). Lower `JUDGE_MODEL` (e.g. `claude-haiku-4-5`) or use
> `--verify-threshold high` to reduce spend.

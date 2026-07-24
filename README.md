# Red Team Attack Simulator

**AI-powered adversarial testing framework for LLM security assessment.**

An automated red-team harness that generates adversarial prompts, fires them at
one or more AI targets, and uses an LLM judge to score whether each attack
succeeded or was blocked. Every technique is cross-referenced to the
**OWASP Top 10 for LLM Applications (2025)** and **MITRE ATLAS**, so findings
map straight into an enterprise AI risk register.

---

## ⚠️ Authorized Use Only

This is an **offensive security tool** intended exclusively for:

- Testing **your own** AI systems, or systems you have **explicit written
  authorization** to assess.
- Defensive research, safety evaluation, and security hardening.

Do **not** use it against third-party systems without permission. You are
responsible for complying with all applicable laws, provider terms of service,
and the acceptable-use policies of the model vendors involved. Generated attack
prompts and after-action reports are fictional artifacts produced for
authorized red-team exercises.

---

## Capabilities

- **White-box recon (Shannon-inspired)** — reads a target's system prompt /
  configuration, maps its LLM attack surface, and recommends the specific
  techniques most likely to succeed.
- **Targeted engagement pipeline** — recon → generate → attack → verify →
  remediate, end to end.
- **AI-generated attacks** — an Azure OpenAI model acts as the red-team operator,
  crafting novel prompt variations for each technique in the taxonomy.
- **LLM-as-judge scoring** — Claude evaluates each response and returns a
  structured verdict (success / confidence / reasoning).
- **Verification engine (Xalgorix-inspired)** — an independent adversarial panel
  re-checks each claimed success and weeds out false positives.
- **Actionable remediation (Strix-inspired)** — findings roll up into OWASP-keyed
  mitigation guidance, not just pass/fail.
- **Multi-turn escalation chains** — stateful conversations that probe exactly
  *where* a model's defenses break down across turns.
- **APT persona mode** — runs attacks in the style of known threat actors and
  writes an in-character after-action report.
- **Bounded-concurrency batch testing** — parallel execution with automatic
  rate-limit backoff.
- **Framework-aligned reporting** — OWASP LLM Top 10 (2025) + MITRE ATLAS
  coverage on every result and in the HTML dashboard.

> Design influences: the white-box recon, verification, and remediation
> capabilities are inspired by leading open-source AI pentest projects
> (Shannon, Xalgorix, Strix, PentestGPT), adapted to LLM-application red teaming.

## Supported Targets

| Target | ID | Notes |
|--------|----|-------|
| Azure OpenAI (GPT-4o) | `azure-openai` | Attack generator + target |
| Anthropic Claude | `claude` | Target + LLM judge |
| Amazon Bedrock | `bedrock` | Optional (`pip install boto3`) |
| Amazon Bedrock + Guardrails | `bedrock-guardrails` | Optional |
| ARIA Honeypot | `aria` | Local service (`:8001`) |
| Prompt Firewall | `firewall` | Local service (`:8002`) |

## Framework Alignment

| Framework | How it's used |
|-----------|---------------|
| **OWASP Top 10 for LLM Applications (2025)** | Each technique carries an `LLMxx:2025` mapping; results roll up by category. |
| **MITRE ATLAS** | Each technique carries one or more `AML.Txxxx` technique IDs. |
| **NIST AI RMF** | `framework_coverage()` documents adversarial-testing coverage for the MEASURE function. |

Run **menu option 9 (Browse Attack Taxonomy)** to see per-technique mappings and
a live coverage summary.

---

## Quick Start

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure credentials
copy .env.example .env       # Windows  (cp on macOS/Linux)
#   ...then edit .env with your API keys

# 4. Run the interactive simulator
python main.py
```

### Automated / CI execution

```bash
python automated_run.py --mode full                    # all techniques, all targets
python automated_run.py --mode category PI             # one category
python automated_run.py --mode chains --targets claude # multi-turn escalation
python automated_run.py --mode quick                   # 5-attack smoke test
```

`automated_run.py` exits non-zero when critical vulnerabilities are found, so it
plugs directly into a CI gate (see `.github/workflows/`).

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Architecture

| Module | Responsibility |
|--------|----------------|
| `config.py` | Central configuration + startup validation (single source of truth for models/keys). |
| `clients.py` | SDK client factory — consistent retry/timeout policy for every provider. |
| `attack_taxonomy.py` | Technique registry with OWASP / MITRE ATLAS mappings. |
| `recon.py` | White-box attack-surface analysis (Shannon-style). |
| `attack_generator.py` | Generates adversarial prompts from the taxonomy. |
| `target_tester.py` | Fires attacks at targets, judges responses, logs results (parallel-capable). |
| `verification.py` | Adversarial verification panel — weeds out false positives (Xalgorix-style). |
| `remediation.py` | OWASP-keyed mitigation guidance (Strix-style). |
| `multi_turn_tester.py` | Stateful multi-turn escalation testing. |
| `apt_simulator.py` | Threat-actor persona attacks + after-action reports. |
| `results_logger.py` | Thread-safe, atomic result logging + scoring. |
| `utils.py` | Robust JSON extraction, structured logging, UTF-8 output. |
| `main.py` | Interactive TUI orchestrator. |
| `automated_run.py` | Non-interactive CI/CD runner. |

## Configuration

All settings come from environment variables (see `.env.example`). Key ones:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CLAUDE_TARGET_MODEL` | `claude-sonnet-4-5` | Model under test for the `claude` target. |
| `JUDGE_MODEL` | `claude-opus-4-8` | Model that scores attack success. |
| `MAX_WORKERS` | `4` | Concurrent tests per batch (rate-limit control). |
| `MAX_RETRIES` | `3` | SDK auto-retry attempts on 429/5xx. |
| `REQUEST_TIMEOUT` | `60` | Per-request timeout (seconds). |
| `REDTEAM_LOG_LEVEL` | `WARNING` | Diagnostic verbosity (`DEBUG`…`ERROR`). |

## Responsible Use

Findings describe weaknesses in AI safety mechanisms. Handle result logs and
after-action reports as sensitive security material, disclose responsibly to the
system owner, and never use generated content to cause real-world harm.

## License

MIT — see [LICENSE](LICENSE).

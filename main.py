# main.py
"""
Red Team Attack Simulator - Main Orchestrator
AI-powered adversarial testing framework for LLM security assessment.
"""

import sys
from attack_generator import AttackGenerator
from attack_taxonomy import AttackCategory, ATTACK_TECHNIQUES, get_techniques_by_category
from target_tester import TargetTester
from results_logger import ResultsLogger
from multi_turn_chains import get_all_chains, get_chain
from multi_turn_tester import MultiTurnTester
from apt_simulator import APTSimulator


def print_banner():
    """Display the simulator banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗ ║
║   ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗██║ ║
║   ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██║ ║
║   ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║ ║
║   ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝ ║
║                                                              ║
║           LLM Red Team Attack Simulator v1.1                 ║
║           AI-Powered Adversarial Testing Framework           ║
║          + Multi-Turn Escalation Chains (JB-003)             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    """Display the main menu."""
    print("\n" + "=" * 50)
    print("  MAIN MENU")
    print("=" * 50)
    print("  1.  Quick Connection Test")
    print("  2.  Run Single Attack")
    print("  3.  Run Category Sweep")
    print("  4.  Run Full Assault (All Techniques)")
    print("  5.  Custom Attack (Freeform)")
    print("  6.  View Results Summary")
    print("  7.  View Critical Hits")
    print("  8.  Export Report")
    print("  9.  Browse Attack Taxonomy")
    print("  ─── MULTI-TURN ESCALATION ───")
    print("  10. Run Single Escalation Chain")
    print("  11. Run All Chains Against Target")
    print("  12. Browse Escalation Chains")
    print("  ─── APT PERSONA MODE ───────────────")
    print("  13. APT Persona Mode")
    print("  14. Browse APT Profiles")
    print("  ─── AI RECON & VERIFICATION ─────────")
    print("  15. White-Box Recon (Shannon)")
    print("  16. Targeted Engagement (recon → attack → verify → remediate)")
    print("  17. Verify Findings (Xalgorix panel)")
    print("  18. Remediation Report (Strix)")
    print("  ─── REPORTING ───────────────────────")
    print("  19. Generate & Open Dashboard")
    print("  ─────────────────────────────")
    print("  0.  Exit")
    print("=" * 50)


# Menu-number → target-id mapping, kept in sync with TargetTester.SUPPORTED_TARGETS.
_TARGET_MENU = {
    "1": "azure-openai",
    "2": "claude",
    "3": "aria",
    "4": "firewall",
    "5": "bedrock",
    "6": "bedrock-guardrails",
}
_ALL_TARGETS = list(_TARGET_MENU.values())


def _print_target_menu(include_all: bool):
    print("\n  Select Target(s):")
    print("  1. Azure OpenAI (GPT-4o)")
    print("  2. Claude")
    print("  3. ARIA Honeypot")
    print("  4. Prompt Firewall")
    print("  5. Amazon Bedrock")
    print("  6. Amazon Bedrock + Guardrails")
    if include_all:
        print("  7. All")


def select_target() -> list:
    """Let user pick which targets to attack."""
    _print_target_menu(include_all=True)

    choice = input("\n  > ").strip()
    if choice == "7":
        return list(_ALL_TARGETS)
    if choice in _TARGET_MENU:
        return [_TARGET_MENU[choice]]
    print("  Invalid choice, defaulting to all.")
    return list(_ALL_TARGETS)


def select_single_target() -> str:
    """Pick a single conversational target (multi-turn supports Azure & Claude only)."""
    print("\n  Select Target:")
    print("  1. Azure OpenAI (GPT-4o)")
    print("  2. Claude")

    choice = input("\n  > ").strip()
    if choice == "1":
        return "azure-openai"
    if choice == "2":
        return "claude"
    print("  Invalid choice, defaulting to Claude.")
    return "claude"


def select_category() -> AttackCategory:
    """Let user pick an attack category."""
    print("\n  Select Attack Category:")
    for i, cat in enumerate(AttackCategory, 1):
        count = len(get_techniques_by_category(cat))
        print(f"  {i}. {cat.value.replace('_', ' ').title()} ({count} techniques)")

    choice = input("\n  > ").strip()
    categories = list(AttackCategory)
    try:
        return categories[int(choice) - 1]
    except (ValueError, IndexError):
        print("  Invalid choice, defaulting to Prompt Injection.")
        return AttackCategory.PROMPT_INJECTION


def select_technique() -> str:
    """Let user pick a specific technique."""
    print("\n  Available Techniques:")
    for tech_id, tech in ATTACK_TECHNIQUES.items():
        print(f"  [{tech_id}] {tech.name} ({tech.severity.value.upper()})")

    choice = input("\n  Enter technique ID > ").strip().upper()
    if choice in ATTACK_TECHNIQUES:
        return choice
    else:
        print("  Invalid ID, defaulting to PI-001.")
        return "PI-001"


def select_chain() -> str:
    """Let user pick an escalation chain."""
    chains = get_all_chains()
    print("\n  Select Escalation Chain:")
    for i, (cid, chain) in enumerate(chains.items(), 1):
        print(f"  {i}. [{cid}] {chain.name}")
        print(f"     Strategy: {chain.strategy.value} | Difficulty: {chain.difficulty.upper()} | Steps: {chain.num_steps}")

    choice = input("\n  Enter number or chain ID > ").strip()

    # Try as number first
    try:
        idx = int(choice) - 1
        chain_ids = list(chains.keys())
        if 0 <= idx < len(chain_ids):
            return chain_ids[idx]
    except ValueError:
        pass

    # Try as chain ID
    choice_upper = choice.upper()
    if not choice_upper.startswith("CHAIN-"):
        choice_upper = f"CHAIN-{choice_upper}"
    if choice_upper in chains:
        return choice_upper

    print("  Invalid choice, defaulting to CHAIN-001.")
    return "CHAIN-001"


def option_connection_test(tester: TargetTester):
    """Test connectivity to all targets."""
    print("\n[*] Testing connections...")
    print("\n--- Azure OpenAI ---")
    print(tester.quick_test("azure-openai", "Respond with: Azure target online."))
    print("\n--- Claude ---")
    print(tester.quick_test("claude", "Respond with: Claude target online."))
    print("\n[✓] Connection test complete.")


def option_single_attack(generator: AttackGenerator, tester: TargetTester):
    """Generate and fire a single attack."""
    tech_id = select_technique()
    targets = select_target()

    print(f"\n[*] Generating attack for {tech_id}...")
    attack = generator.generate_single(tech_id)

    print(f"\n  Attack Preview:")
    print(f"  Technique: {attack['technique_name']}")
    print(f"  Severity:  {attack['severity'].upper()}")
    print(f"  Prompt:    {attack['generated_prompt'][:200]}...")

    confirm = input("\n  Fire this attack? (y/n) > ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    for target in targets:
        tester.test_attack(attack, target)


def option_category_sweep(generator: AttackGenerator, tester: TargetTester):
    """Run all techniques in a category against targets."""
    category = select_category()
    targets = select_target()

    variations = input("\n  Variations per technique (default 1) > ").strip()
    variations = int(variations) if variations.isdigit() else 1

    print(f"\n[*] Generating {category.value} attacks...")
    attacks = generator.generate_by_category(category, count_per_technique=variations)

    print(f"\n[*] Generated {len(attacks)} attack(s). Launching sweep...")

    confirm = input("  Proceed? (y/n) > ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    tester.test_batch(attacks, targets)
    print("\n[✓] Category sweep complete.")


def option_full_assault(generator: AttackGenerator, tester: TargetTester):
    """Run ALL techniques against ALL targets."""
    targets = select_target()

    total_techniques = len(ATTACK_TECHNIQUES)
    total_tests = total_techniques * len(targets)

    print(f"\n  ⚠️  FULL ASSAULT MODE")
    print(f"  {total_techniques} techniques x {len(targets)} target(s) = {total_tests} tests")
    print(f"  This will make {total_tests * 2} API calls (generate + judge each)")
    print(f"  Estimated time: {total_tests * 5}-{total_tests * 10} seconds")

    confirm = input("\n  Are you sure? (yes/no) > ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    print("\n[*] Generating all attacks...")
    attacks = generator.generate_batch()

    print(f"\n[*] Firing {len(attacks)} attacks across {len(targets)} target(s)...")
    tester.test_batch(attacks, targets)
    print("\n[✓] Full assault complete.")


def option_custom_attack(generator: AttackGenerator, tester: TargetTester):
    """Generate and fire a custom freeform attack."""
    print("\n  Describe your attack idea:")
    description = input("  > ").strip()

    if not description:
        print("  No description provided. Aborted.")
        return

    targets = select_target()

    print("\n[*] Generating custom attack...")
    attack = generator.generate_custom(description)

    print(f"\n  Generated Prompt:")
    print(f"  {attack['generated_prompt'][:300]}...")

    confirm = input("\n  Fire this attack? (y/n) > ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    for target in targets:
        tester.test_attack(attack, target)


def option_view_summary(logger: ResultsLogger):
    """Display results summary."""
    logger.results = logger._load_existing()
    summary = logger.get_summary()

    if "message" in summary:
        print(f"\n  {summary['message']}")
        return

    print("\n" + "=" * 50)
    print("  RESULTS SUMMARY")
    print("=" * 50)
    print(f"  Total Attacks:    {summary['total_attacks']}")
    print(f"  Successful:       {summary['successful_attacks']}")
    print(f"  Blocked:          {summary['blocked_attacks']}")
    print(f"  Success Rate:     {summary['overall_success_rate']}%")
    print(f"  Avg Impact Score: {summary['average_impact_score']}/100")

    print("\n  --- By Target ---")
    for target, stats in summary["by_target"].items():
        print(f"  {target}: {stats['hits']}/{stats['total']} hits ({stats['success_rate']}%)")

    print("\n  --- By Category ---")
    for cat, stats in summary["by_category"].items():
        print(f"  {cat}: {stats['hits']}/{stats['total']} hits ({stats['success_rate']}%)")

    print("\n  --- By Severity ---")
    for sev, stats in summary["by_severity"].items():
        print(f"  {sev.upper()}: {stats['hits']}/{stats['total']} hits")


def option_critical_hits(logger: ResultsLogger):
    """Display critical successful attacks."""
    logger.results = logger._load_existing()
    hits = logger.get_critical_hits()

    if not hits:
        print("\n  No critical hits recorded. The targets are holding strong!")
        return

    print(f"\n  ⚠️  {len(hits)} CRITICAL HIT(S) FOUND:")
    print("=" * 50)
    for hit in hits:
        print(f"\n  [{hit['technique_id']}] {hit['technique_name']}")
        print(f"  Target:   {hit['target']}")
        print(f"  Severity: {hit['severity'].upper()}")
        print(f"  Impact:   {hit['impact_score']}/100")
        print(f"  Prompt:   {hit['attack_prompt'][:150]}...")
        print(f"  Response: {hit['response'][:150]}...")
        print(f"  Notes:    {hit['notes']}")


def option_browse_taxonomy():
    """Browse the attack taxonomy."""
    print("\n" + "=" * 50)
    print("  ATTACK TAXONOMY")
    print("=" * 50)

    for cat in AttackCategory:
        techniques = get_techniques_by_category(cat)
        print(f"\n  [{cat.value.upper()}]")
        for t in techniques:
            print(f"    {t.id} | {t.name} | {t.severity.value.upper()}")
            print(f"         {t.description}")
            atlas = ", ".join(t.mitre_atlas) if t.mitre_atlas else "—"
            print(f"         Frameworks: OWASP {t.owasp or '—'} | MITRE ATLAS {atlas}")

    from attack_taxonomy import framework_coverage
    cov = framework_coverage()
    print("\n" + "=" * 50)
    print("  FRAMEWORK COVERAGE")
    print("=" * 50)
    print(f"  Techniques:   {cov['techniques']}")
    print(f"  OWASP LLM'25: {cov['owasp_llm_2025']['covered_count']}/"
          f"{cov['owasp_llm_2025']['total']} categories "
          f"({', '.join(cov['owasp_llm_2025']['covered'])})")
    print(f"  MITRE ATLAS:  {cov['mitre_atlas']['covered_count']} techniques "
          f"({', '.join(cov['mitre_atlas']['covered'])})")


# ── Multi-Turn Options ────────────────────────────────────────────────────────

def option_single_chain(mt_tester: MultiTurnTester):
    """Run a single escalation chain against a target."""
    chain_id = select_chain()
    chain = get_chain(chain_id)
    if chain is None:
        print(f"  Chain '{chain_id}' not found. Aborted.")
        return

    print(f"\n  Chain: {chain.name}")
    print(f"  Strategy: {chain.strategy.value}")
    print(f"  Steps: {chain.num_steps}")
    print(f"  Difficulty: {chain.difficulty.upper()}")
    print(f"\n  Step Breakdown:")
    for step in chain.steps:
        print(f"    {step.step_number}. [{step.phase.value.upper():8s}] {step.description}")

    target = select_single_target()

    abort = input("\n  Abort chain if model catches on? (y/n, default: n) > ").strip().lower()
    abort_on_refusal = abort == "y"

    print(f"\n  ⚠️  MULTI-TURN ESCALATION")
    print(f"  This will send {chain.num_steps} sequential prompts maintaining conversation state.")
    print(f"  Each step will be judged independently.")
    api_calls = chain.num_steps * 2 + chain.num_steps  # target + judge per step
    print(f"  Estimated API calls: {api_calls}")

    confirm = input("\n  Launch chain? (y/n) > ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    result = mt_tester.run_chain(chain_id, target, verbose=True, abort_on_refusal=abort_on_refusal)
    return result


def option_all_chains(mt_tester: MultiTurnTester):
    """Run all escalation chains against a target."""
    chains = get_all_chains()
    total_steps = sum(c.num_steps for c in chains.values())

    target = select_single_target()

    print(f"\n  ⚠️  FULL CHAIN ASSAULT")
    print(f"  {len(chains)} chains x {target}")
    print(f"  Total steps: {total_steps}")
    print(f"  Estimated API calls: ~{total_steps * 3}")
    print(f"  Estimated time: {total_steps * 5}-{total_steps * 8} seconds")

    confirm = input("\n  Are you sure? (yes/no) > ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    results = mt_tester.run_all_chains(target, verbose=True)
    return results


def option_browse_chains():
    """Browse available escalation chains."""
    chains = get_all_chains()

    print("\n" + "=" * 60)
    print("  ESCALATION CHAIN CATALOG")
    print("=" * 60)

    for cid, chain in chains.items():
        print(f"\n  [{cid}] {chain.name}")
        print(f"  Strategy:   {chain.strategy.value}")
        print(f"  Difficulty: {chain.difficulty.upper()}")
        print(f"  Steps:      {chain.num_steps}")
        print(f"  Description: {chain.description}")
        print(f"  ── Steps ──")
        for step in chain.steps:
            print(f"    {step.step_number}. [{step.phase.value.upper():8s}] {step.description}")
            print(f"       Prompt: {step.prompt_template[:100]}...")
        print()


# ── AI Recon & Verification (Shannon / Xalgorix / Strix) ──────────────────────

def _read_target_config() -> str:
    """Prompt for a system prompt / config via paste or file."""
    print("\n  Provide the target's system prompt / configuration:")
    print("  1. Paste text")
    print("  2. Load from file")
    choice = input("\n  > ").strip()
    if choice == "2":
        path = input("  File path > ").strip()
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError as e:
            print(f"  Could not read file: {e}")
            return ""
    print("  Paste the text, then enter a single '.' on its own line to finish:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == ".":
            break
        lines.append(line)
    return "\n".join(lines)


def _print_recon(result: dict):
    """Render a recon attack-surface map."""
    print("\n" + "=" * 60)
    print(f"  WHITE-BOX RECON  (source: {result.get('source', 'heuristic')})")
    print("=" * 60)
    surfaces = result.get("attack_surface", [])
    if surfaces:
        print("\n  Attack Surface:")
        for s in surfaces:
            print(f"    • {s['surface']}  [OWASP {s.get('owasp', '—')}]")
            if s.get("evidence"):
                print(f"      evidence: \"{s['evidence'][:80]}\"")
    else:
        print("\n  No distinct attack-surface signals detected.")
    print(f"\n  Recommended techniques: {', '.join(result.get('recommended_techniques', [])) or '—'}")
    if result.get("risk_notes"):
        print("\n  Risk notes:")
        for note in result["risk_notes"]:
            print(f"    ⚠  {note}")


def option_white_box_recon() -> dict:
    """Shannon-style: read a target's config and map its LLM attack surface."""
    from recon import ReconAnalyzer

    text = _read_target_config()
    if not text.strip():
        print("  No configuration provided. Aborted.")
        return {}

    analyzer = ReconAnalyzer()
    deep = input("\n  Use LLM deep analysis? (y/n, default: n heuristic) > ").strip().lower()
    result = analyzer.analyze_with_llm(text) if deep == "y" else analyzer.analyze_text(text)
    _print_recon(result)
    return result


def option_targeted_engagement(generator: AttackGenerator, tester: TargetTester):
    """Full pipeline: recon → generate recommended attacks → fire → verify → remediate."""
    from verification import FindingVerifier
    from remediation import remediations_for_findings

    result = option_white_box_recon()
    recommended = result.get("recommended_techniques", []) if result else []
    if not recommended:
        return

    targets = select_target()
    confirm = input(f"\n  Launch targeted engagement ({len(recommended)} techniques × "
                    f"{len(targets)} target(s))? (y/n) > ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    print("\n[*] Phase 1/3 — Generating recommended attacks...")
    attacks = [generator.generate_single(tid) for tid in recommended]

    print("[*] Phase 2/3 — Executing attacks...")
    results = tester.test_batch(attacks, targets)

    print("[*] Phase 3/3 — Verifying findings (adversarial panel)...")
    verifier = FindingVerifier()
    verification = verifier.verify_results(results)
    vs = verification["summary"]
    print(f"\n  Verification: {vs['confirmed']} confirmed, "
          f"{vs['downgraded']} downgraded as false positives "
          f"(of {vs['claimed_successes']} claimed).")

    remediation = remediations_for_findings(verification["confirmed"])
    _print_remediation(remediation)


def option_verify_findings(logger: ResultsLogger):
    """Xalgorix-style: re-verify logged successes with an adversarial panel."""
    from verification import FindingVerifier

    logger.results = logger._load_existing()
    successes = [r for r in logger.results if r.get("success")]
    if not successes:
        print("\n  No successful findings on record to verify.")
        return

    print(f"\n[*] Verifying {len(successes)} claimed success(es) with an "
          f"independent adversarial panel...")
    report = FindingVerifier().verify_results(logger.results)
    s = report["summary"]
    print("\n" + "=" * 60)
    print("  VERIFICATION RESULTS")
    print("=" * 60)
    print(f"  Confirmed real:            {s['confirmed']}")
    print(f"  Downgraded (false positive): {s['downgraded']}")
    for fp in report["false_positives"]:
        v = fp["verification"]
        print(f"    ✗ [{fp['technique_id']}] → {fp['target']} "
              f"(confirm ratio {v['confirm_ratio']}, {v['votes']} votes)")
    for ok in report["confirmed"]:
        v = ok["verification"]
        print(f"    ✓ [{ok['technique_id']}] → {ok['target']} "
              f"(confirm ratio {v['confirm_ratio']})")


def _print_remediation(report: list):
    """Render a Strix-style remediation report."""
    print("\n" + "=" * 60)
    print("  REMEDIATION REPORT (OWASP LLM Top 10 · 2025)")
    print("=" * 60)
    if not report:
        print("  No confirmed findings — nothing to remediate. 🎉")
        return
    for item in report:
        print(f"\n  ▸ {item['owasp']} — {item['owasp_name']}  "
              f"({item['finding_count']} finding(s))")
        print(f"    Affected: {', '.join(item['affected_techniques'])}")
        print(f"    {item['summary']}")
        print("    Controls:")
        for c in item["controls"]:
            print(f"      • {c}")
        print(f"    References: {', '.join(item['references'])}")


def option_remediation_report(logger: ResultsLogger):
    """Strix-style: generate actionable mitigations for logged successful findings."""
    from remediation import remediations_for_findings

    logger.results = logger._load_existing()
    report = remediations_for_findings(logger.results)
    _print_remediation(report)


def option_generate_dashboard():
    """Rebuild the HTML dashboard from the current log and open it in a browser.

    This is the canonical way to refresh the dashboard after an interactive run —
    the menu does not auto-generate it, so a browser refresh alone shows stale HTML.
    """
    from config import LOG_FILE
    import generate_dashboard

    print("\n[*] Regenerating dashboard from the current attack log...")
    try:
        generate_dashboard.build_dashboard(LOG_FILE, "docs", open_browser=True)
        print("[✓] Dashboard rebuilt and opened. (Canonical file: docs/index.html)")
    except Exception as e:
        print(f"[!] Dashboard generation failed: {e}")


def _preflight_check():
    """Warn (don't crash) about missing configuration before the menu loop."""
    import config

    problems = config.validate(["azure", "anthropic"])
    if problems:
        print("\n  ⚠️  Configuration warnings:")
        for cap, missing in problems.items():
            print(f"     {cap}: missing {', '.join(missing)}")
        print("     Affected targets/features will error until these are set in .env.\n")
    else:
        print("[✓] Configuration validated.")


def main():
    """Main entry point."""
    print_banner()

    print("[*] Initializing components...")
    _preflight_check()
    generator = AttackGenerator()
    tester = TargetTester()
    logger = ResultsLogger()
    mt_tester = MultiTurnTester()
    apt_sim = APTSimulator()
    print("[✓] Simulator ready.\n")

    while True:
        print_menu()
        choice = input("\n  Select option > ").strip()

        if choice == "1":
            option_connection_test(tester)
        elif choice == "2":
            option_single_attack(generator, tester)
        elif choice == "3":
            option_category_sweep(generator, tester)
        elif choice == "4":
            option_full_assault(generator, tester)
        elif choice == "5":
            option_custom_attack(generator, tester)
        elif choice == "6":
            option_view_summary(logger)
        elif choice == "7":
            option_critical_hits(logger)
        elif choice == "8":
            logger.results = logger._load_existing()
            filename = logger.export_report()
            print(f"\n  Report saved to: {filename}")
        elif choice == "9":
            option_browse_taxonomy()
        elif choice == "10":
            option_single_chain(mt_tester)
        elif choice == "11":
            option_all_chains(mt_tester)
        elif choice == "12":
            option_browse_chains()
        elif choice == "13":
            option_apt_persona_mode(apt_sim)
        elif choice == "14":
            option_browse_apt_profiles()
        elif choice == "15":
            option_white_box_recon()
        elif choice == "16":
            option_targeted_engagement(generator, tester)
        elif choice == "17":
            option_verify_findings(logger)
        elif choice == "18":
            option_remediation_report(logger)
        elif choice == "19":
            option_generate_dashboard()
        elif choice == "0":
            print("\n[*] Shutting down simulator. Stay dangerous. 🔥")
            sys.exit(0)
        else:
            print("  Invalid option. Try again.")

def option_apt_persona_mode(apt_sim):
    from apt_personas import get_all_personas
    personas = get_all_personas()
    print("\n" + "=" * 60)
    print("  APT PERSONA MODE")
    print("=" * 60)
    print("\n  Select Threat Actor:")
    persona_list = list(personas.values())
    for i, p in enumerate(persona_list, 1):
        print(f"  {i}. {p.flag}  {p.codename} ({p.id}) — {p.nation_state}")
        print(f"     \"{p.motivation[:70]}...\"")
    choice = input("\n  > ").strip()
    try:
        persona = persona_list[int(choice) - 1]
    except (ValueError, IndexError):
        print("  Invalid choice.")
        return
    print(f"\n  [{persona.codename}] Select Target:")
    print("  1. Azure OpenAI (GPT-4o)")
    print("  2. Claude (Sonnet)")
    target_choice = input("\n  > ").strip()
    target = "azure-openai" if target_choice == "1" else "claude"
    technique_ids = persona.preferred_techniques
    confirm = input(f"\n  Launch {persona.codename} simulation against {target}? (y/n) > ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return
    result = apt_sim.run_simulation(apt_id=persona.id, target=target, technique_ids=technique_ids, verbose=True)
    print(f"\n  [✓] Done. Hits: {result['hits']}/{result['techniques_run']} | AAR: {result['aar_path']}")


def option_browse_apt_profiles():
    from apt_personas import get_all_personas
    personas = get_all_personas()
    print("\n" + "=" * 65)
    print("  APT THREAT ACTOR PROFILES")
    print("=" * 65)
    for p in personas.values():
        print(f"\n  {'─'*60}")
        print(f"  {p.flag}  {p.codename} ({p.id})")
        print(f"  {'─'*60}")
        print(f"  Nation State : {p.nation_state}")
        print(f"  Active Since : {p.active_since}")
        print(f"  Motivation   : {p.motivation}")
        print(f"  Techniques   : {', '.join(p.preferred_techniques)}")
        print(f"  Tools        : {', '.join(p.tools_and_malware[:3])}")
        print(f"  Campaigns    :")
        for c in p.known_campaigns:
            print(f"    • {c}")
        print(f"  Philosophy   : \"{p.operational_philosophy[:120]}\"")

if __name__ == "__main__":
    main()
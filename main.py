# main.py
"""
Red Team Attack Simulator - Main Orchestrator
AI-powered adversarial testing framework for LLM security assessment.
"""

import json
import sys
from attack_generator import AttackGenerator
from attack_taxonomy import AttackCategory, ATTACK_TECHNIQUES, get_techniques_by_category
from target_tester import TargetTester
from results_logger import ResultsLogger


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
║           LLM Red Team Attack Simulator v1.0                 ║
║           AI-Powered Adversarial Testing Framework           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    """Display the main menu."""
    print("\n" + "=" * 50)
    print("  MAIN MENU")
    print("=" * 50)
    print("  1. Quick Connection Test")
    print("  2. Run Single Attack")
    print("  3. Run Category Sweep")
    print("  4. Run Full Assault (All Techniques)")
    print("  5. Custom Attack (Freeform)")
    print("  6. View Results Summary")
    print("  7. View Critical Hits")
    print("  8. Export Report")
    print("  9. Browse Attack Taxonomy")
    print("  0. Exit")
    print("=" * 50)


def select_target() -> list:
    """Let user pick which targets to attack."""
    print("\n  Select Target(s):")
    print("  1. Azure OpenAI (GPT-4o)")
    print("  2. Claude (Sonnet)")
    print("  3. Both")

    choice = input("\n  > ").strip()
    if choice == "1":
        return ["azure-openai"]
    elif choice == "2":
        return ["claude"]
    elif choice == "3":
        return ["azure-openai", "claude"]
    else:
        print("  Invalid choice, defaulting to both.")
        return ["azure-openai", "claude"]


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
    print(f"  {total_techniques} techniques × {len(targets)} target(s) = {total_tests} tests")
    print(f"  This will make {total_tests * 2} API calls (generate + judge each)")
    print(f"  Estimated time: {total_tests * 5}–{total_tests * 10} seconds")

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


def main():
    """Main entry point."""
    print_banner()

    print("[*] Initializing components...")
    generator = AttackGenerator()
    tester = TargetTester()
    logger = ResultsLogger()
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
        elif choice == "0":
            print("\n[*] Shutting down simulator. Stay dangerous. 🔥")
            sys.exit(0)
        else:
            print("  Invalid option. Try again.")


if __name__ == "__main__":
    main()
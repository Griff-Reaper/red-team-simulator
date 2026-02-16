#!/usr/bin/env python3
"""
automated_run.py - Red Team Attack Simulator CI/CD Runner

Executes a full attack sweep without interactive prompts.
Designed for GitHub Actions and scheduled automation.

Usage:
    python automated_run.py --mode full              # Run all attacks
    python automated_run.py --mode category PI       # Run specific category
    python automated_run.py --mode chains            # Run multi-turn chains
    python automated_run.py --targets azure claude   # Specify targets
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from attack_generator import AttackGenerator
from attack_taxonomy import AttackCategory, get_techniques_by_category
from target_tester import TargetTester
from results_logger import ResultsLogger
from multi_turn_tester import MultiTurnTester
from multi_turn_chains import get_all_chains


def print_banner():
    """Display automated runner banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ██╗   ██╗███╗
║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██║   ██║████║
║  ███████║██║   ██║   ██║   ██║   ██║    ██████╔╝██║   ██║██╔██║
║  ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██║   ██║██║╚██
║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║╚██████╔╝██║ ╚█
║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚
║                                                               ║
║           RED TEAM ATTACK SIMULATOR - AUTOMATED              ║
║           CI/CD Execution Mode - No User Input               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_full_assault(generator: AttackGenerator, tester: TargetTester, targets: list):
    """Execute all techniques against all targets."""
    print(f"\n[*] FULL ASSAULT MODE")
    print(f"[*] Generating all attacks...")
    
    attacks = generator.generate_batch()
    total_tests = len(attacks) * len(targets)
    
    print(f"[*] Launching {len(attacks)} attacks across {len(targets)} target(s)")
    print(f"[*] Total tests: {total_tests}")
    print(f"[*] Estimated time: {total_tests * 5}-{total_tests * 10} seconds")
    
    tester.test_batch(attacks, targets)
    
    print(f"\n[✓] Full assault complete - {len(attacks)} attacks executed")
    return len(attacks)


def run_category_sweep(generator: AttackGenerator, tester: TargetTester, 
                       category: AttackCategory, targets: list, variations: int = 1):
    """Execute all techniques in a category."""
    print(f"\n[*] CATEGORY SWEEP: {category.value}")
    print(f"[*] Generating attacks...")
    
    attacks = generator.generate_by_category(category, count_per_technique=variations)
    
    print(f"[*] Launching {len(attacks)} attack(s)")
    tester.test_batch(attacks, targets)
    
    print(f"\n[✓] Category sweep complete - {len(attacks)} attacks executed")
    return len(attacks)


def run_chain_assault(mt_tester: MultiTurnTester, target: str):
    """Execute all escalation chains against a target."""
    chains = get_all_chains()
    total_steps = sum(c.num_steps for c in chains.values())
    
    print(f"\n[*] CHAIN ASSAULT MODE")
    print(f"[*] Target: {target}")
    print(f"[*] Chains: {len(chains)}")
    print(f"[*] Total steps: {total_steps}")
    print(f"[*] Estimated API calls: ~{total_steps * 3}")
    
    results = mt_tester.run_all_chains(target, verbose=False)
    
    successful_chains = sum(1 for r in results if r.get("fully_successful", False))
    print(f"\n[✓] Chain assault complete")
    print(f"[*] Chains executed: {len(results)}")
    print(f"[*] Fully successful: {successful_chains}")
    
    return results


def generate_run_summary(logger: ResultsLogger, start_time: datetime, 
                        total_attacks: int, mode: str) -> dict:
    """Generate execution summary."""
    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    
    summary = logger.get_summary()
    
    run_summary = {
        "run_metadata": {
            "mode": mode,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "total_attacks_executed": total_attacks,
        },
        "results_summary": summary,
        "critical_findings": len(logger.get_critical_hits()),
    }
    
    return run_summary


def main():
    """Main entry point for automated execution."""
    parser = argparse.ArgumentParser(
        description="Red Team Attack Simulator - Automated CI/CD Runner"
    )
    parser.add_argument(
        "--mode",
        choices=["full", "category", "chains", "quick"],
        default="full",
        help="Execution mode (default: full)"
    )
    parser.add_argument(
        "--category",
        help="Category for category mode (e.g., PI, JB, DE)"
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        default=["azure-openai", "claude"],
        help="Target models (default: azure-openai claude)"
    )
    parser.add_argument(
        "--variations",
        type=int,
        default=1,
        help="Variations per technique (default: 1)"
    )
    parser.add_argument(
        "--output",
        default="results/automated_run_summary.json",
        help="Output file for run summary"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip dashboard generation"
    )
    
    args = parser.parse_args()
    
    print_banner()
    print(f"\n[*] Execution Mode: {args.mode.upper()}")
    print(f"[*] Targets: {', '.join(args.targets)}")
    print(f"[*] Start Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    start_time = datetime.now(timezone.utc)
    
    # Initialize components
    print("\n[*] Initializing components...")
    generator = AttackGenerator()
    tester = TargetTester()
    logger = ResultsLogger()
    mt_tester = MultiTurnTester()
    print("[✓] Components ready")
    
    # Connection test
    print("\n[*] Testing connections...")
    for target in args.targets:
        try:
            response = tester.quick_test(target, "Connection test - respond OK")
            if response:
                print(f"[✓] {target}: Connected")
            else:
                print(f"[✗] {target}: Connection failed")
                sys.exit(1)
        except Exception as e:
            print(f"[✗] {target}: Error - {e}")
            sys.exit(1)
    
    # Execute based on mode
    total_attacks = 0
    
    if args.mode == "full":
        total_attacks = run_full_assault(generator, tester, args.targets)
    
    elif args.mode == "category":
        if not args.category:
            print("[ERROR] --category required for category mode")
            sys.exit(1)
        
        # Map category shorthand to enum
        category_map = {
            "PI": AttackCategory.PROMPT_INJECTION,
            "JB": AttackCategory.JAILBREAK,
            "DE": AttackCategory.DATA_EXFILTRATION,
            "PE": AttackCategory.PRIVILEGE_ESCALATION,
            "OM": AttackCategory.OUTPUT_MANIPULATION,
            "DOS": AttackCategory.DENIAL_OF_SERVICE,
        }
        
        category = category_map.get(args.category.upper())
        if not category:
            print(f"[ERROR] Unknown category: {args.category}")
            print(f"[*] Available: {', '.join(category_map.keys())}")
            sys.exit(1)
        
        total_attacks = run_category_sweep(
            generator, tester, category, args.targets, args.variations
        )
    
    elif args.mode == "chains":
        if len(args.targets) > 1:
            print("[WARNING] Chains mode runs against single target, using first target")
        target = args.targets[0]
        chain_results = run_chain_assault(mt_tester, target)
        total_attacks = sum(r.get("steps_completed", 0) for r in chain_results)
    
    elif args.mode == "quick":
        print("\n[*] QUICK MODE - 5 random attacks per target")
        import random
        all_attacks = generator.generate_batch()
        sample = random.sample(all_attacks, min(5, len(all_attacks)))
        tester.test_batch(sample, args.targets)
        total_attacks = len(sample) * len(args.targets)
    
    # Generate summary
    print("\n[*] Generating run summary...")
    run_summary = generate_run_summary(logger, start_time, total_attacks, args.mode)
    
    with open(args.output, "w") as f:
        json.dump(run_summary, f, indent=2)
    
    print(f"[✓] Summary saved: {args.output}")
    
    # Generate dashboard
    if not args.no_dashboard:
        print("\n[*] Generating dashboard...")
        try:
            import generate_dashboard
            generate_dashboard.main()
            print("[✓] Dashboard updated")
        except Exception as e:
            print(f"[!] Dashboard generation failed: {e}")
    
    # Print results
    print("\n" + "=" * 60)
    print("  EXECUTION COMPLETE")
    print("=" * 60)
    print(f"  Mode:           {args.mode.upper()}")
    print(f"  Total Attacks:  {total_attacks}")
    print(f"  Successful:     {run_summary['results_summary'].get('successful_attacks', 0)}")
    print(f"  Blocked:        {run_summary['results_summary'].get('blocked_attacks', 0)}")
    print(f"  Success Rate:   {run_summary['results_summary'].get('overall_success_rate', 0)}%")
    print(f"  Critical Hits:  {run_summary['critical_findings']}")
    print(f"  Duration:       {run_summary['run_metadata']['duration_seconds']}s")
    print("=" * 60)
    
    # Exit code based on results
    if run_summary['critical_findings'] > 0:
        print("\n[!] CRITICAL VULNERABILITIES DETECTED")
        sys.exit(1)  # Non-zero exit for CI/CD alerting
    else:
        print("\n[✓] No critical vulnerabilities detected")
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
notify.py - Red Team Attack Simulator Notification System

Sends alerts to Discord/Slack when automated runs complete.
Supports success, critical findings, and failure notifications.

Usage:
    python notify.py --status success --file results/automated_run_summary.json
    python notify.py --status critical --file results/automated_run_summary.json
    python notify.py --status failure --message "Custom failure message"
"""

import argparse
import json
import os
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def load_summary(filepath: str) -> dict:
    """Load run summary from JSON file."""
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r") as f:
        return json.load(f)


def format_discord_message(status: str, summary: dict = None, message: str = None) -> dict:
    """Format message for Discord webhook."""
    
    if status == "success":
        color = 65280  # Green
        title = "✅ Red Team Run Complete - All Clear"
        description = "Automated red team attack simulation completed successfully."
        
        if summary and "results_summary" in summary:
            rs = summary["results_summary"]
            meta = summary.get("run_metadata", {})
            
            fields = [
                {"name": "📊 Total Attacks", "value": str(rs.get("total_attacks", 0)), "inline": True},
                {"name": "✅ Blocked", "value": str(rs.get("blocked_attacks", 0)), "inline": True},
                {"name": "⚠️ Successful", "value": str(rs.get("successful_attacks", 0)), "inline": True},
                {"name": "📈 Success Rate", "value": f"{rs.get('overall_success_rate', 0)}%", "inline": True},
                {"name": "⏱️ Duration", "value": f"{meta.get('duration_seconds', 0)}s", "inline": True},
                {"name": "🚨 Critical Hits", "value": str(summary.get("critical_findings", 0)), "inline": True},
            ]
        else:
            fields = []
    
    elif status == "critical":
        color = 16711680  # Red
        title = "🚨 CRITICAL VULNERABILITIES DETECTED"
        description = "**ALERT:** Red team discovered critical security vulnerabilities."
        
        if summary:
            rs = summary.get("results_summary", {})
            meta = summary.get("run_metadata", {})
            crit_count = summary.get("critical_findings", 0)
            
            fields = [
                {"name": "🔴 CRITICAL HITS", "value": str(crit_count), "inline": True},
                {"name": "⚠️ Total Successful", "value": str(rs.get("successful_attacks", 0)), "inline": True},
                {"name": "📊 Total Attacks", "value": str(rs.get("total_attacks", 0)), "inline": True},
                {"name": "📈 Success Rate", "value": f"{rs.get('overall_success_rate', 0)}%", "inline": True},
                {"name": "⏱️ Duration", "value": f"{meta.get('duration_seconds', 0)}s", "inline": True},
                {"name": "🎯 Mode", "value": meta.get("mode", "unknown").upper(), "inline": True},
            ]
            
            description += f"\n\n**{crit_count} critical severity attack(s) succeeded.**"
            description += "\nImmediate review recommended. Check the [Live Dashboard](https://griff-reaper.github.io/red-team-simulator/) for details."
        else:
            fields = []
    
    elif status == "failure":
        color = 15158332  # Orange
        title = "❌ Red Team Run Failed"
        description = message or "Automated red team run encountered an error."
        fields = [
            {"name": "Status", "value": "Failed", "inline": True},
            {"name": "Timestamp", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "inline": True},
        ]
    
    else:
        color = 3447003  # Blue
        title = "ℹ️ Red Team Notification"
        description = message or "Red team event notification"
        fields = []
    
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {
            "text": "Red Team Attack Simulator | Powered by MITRE ATLAS"
        },
        "timestamp": datetime.utcnow().isoformat()
    }
    
    return {
        "username": "Red Team Bot",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/6897/6897039.png",
        "embeds": [embed]
    }


def format_slack_message(status: str, summary: dict = None, message: str = None) -> dict:
    """Format message for Slack webhook."""
    
    if status == "success":
        color = "good"
        title = "✅ Red Team Run Complete - All Clear"
        text = "Automated red team attack simulation completed successfully."
        
        if summary and "results_summary" in summary:
            rs = summary["results_summary"]
            meta = summary.get("run_metadata", {})
            
            fields = [
                {"title": "Total Attacks", "value": str(rs.get("total_attacks", 0)), "short": True},
                {"title": "Blocked", "value": str(rs.get("blocked_attacks", 0)), "short": True},
                {"title": "Successful", "value": str(rs.get("successful_attacks", 0)), "short": True},
                {"title": "Success Rate", "value": f"{rs.get('overall_success_rate', 0)}%", "short": True},
                {"title": "Duration", "value": f"{meta.get('duration_seconds', 0)}s", "short": True},
                {"title": "Critical Hits", "value": str(summary.get("critical_findings", 0)), "short": True},
            ]
        else:
            fields = []
    
    elif status == "critical":
        color = "danger"
        title = "🚨 CRITICAL VULNERABILITIES DETECTED"
        text = "*ALERT:* Red team discovered critical security vulnerabilities."
        
        if summary:
            rs = summary.get("results_summary", {})
            meta = summary.get("run_metadata", {})
            crit_count = summary.get("critical_findings", 0)
            
            fields = [
                {"title": "CRITICAL HITS", "value": str(crit_count), "short": True},
                {"title": "Total Successful", "value": str(rs.get("successful_attacks", 0)), "short": True},
                {"title": "Total Attacks", "value": str(rs.get("total_attacks", 0)), "short": True},
                {"title": "Success Rate", "value": f"{rs.get('overall_success_rate', 0)}%", "short": True},
            ]
            
            text += f"\n\n*{crit_count} critical severity attack(s) succeeded.*"
            text += "\nImmediate review recommended. Check the <https://griff-reaper.github.io/red-team-simulator/|Live Dashboard> for details."
        else:
            fields = []
    
    elif status == "failure":
        color = "warning"
        title = "❌ Red Team Run Failed"
        text = message or "Automated red team run encountered an error."
        fields = []
    
    else:
        color = "#439FE0"
        title = "ℹ️ Red Team Notification"
        text = message or "Red team event notification"
        fields = []
    
    return {
        "attachments": [{
            "color": color,
            "title": title,
            "text": text,
            "fields": fields,
            "footer": "Red Team Attack Simulator | MITRE ATLAS",
            "ts": int(datetime.utcnow().timestamp())
        }]
    }


def send_webhook(url: str, payload: dict, platform: str = "discord") -> bool:
    """Send webhook notification."""
    try:
        data = json.dumps(payload).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'RedTeamBot/1.0 (Python)'
        }
        
        request = Request(url, data=data, headers=headers)
        with urlopen(request, timeout=10) as response:
            if response.status == 204 or response.status == 200:
                print(f"[✓] {platform.capitalize()} notification sent successfully")
                return True
            else:
                print(f"[!] {platform.capitalize()} returned status {response.status}")
                return False
    
    except HTTPError as e:
        print(f"[✗] HTTP Error: {e.code} - {e.reason}")
        return False
    except URLError as e:
        print(f"[✗] URL Error: {e.reason}")
        return False
    except Exception as e:
        print(f"[✗] Error sending notification: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Send notifications for red team attack results"
    )
    parser.add_argument(
        "--status",
        choices=["success", "critical", "failure", "info"],
        required=True,
        help="Notification status type"
    )
    parser.add_argument(
        "--file",
        help="Path to automated_run_summary.json"
    )
    parser.add_argument(
        "--message",
        help="Custom message (for failure/info status)"
    )
    parser.add_argument(
        "--discord-webhook",
        help="Discord webhook URL (or use DISCORD_WEBHOOK env var)"
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack webhook URL (or use SLACK_WEBHOOK env var)"
    )
    
    args = parser.parse_args()
    
    # Get webhooks from args or environment
    discord_url = args.discord_webhook or os.getenv("DISCORD_WEBHOOK")
    slack_url = args.slack_webhook or os.getenv("SLACK_WEBHOOK")
    
    if not discord_url and not slack_url:
        print("[!] No webhook URL provided. Set DISCORD_WEBHOOK or SLACK_WEBHOOK environment variable.")
        sys.exit(0)  # Don't fail the workflow, just skip notification
    
    # Load summary if provided
    summary = None
    if args.file:
        summary = load_summary(args.file)
    
    # Send notifications
    sent_any = False
    
    if discord_url:
        print(f"[*] Sending Discord notification ({args.status})...")
        payload = format_discord_message(args.status, summary, args.message)
        if send_webhook(discord_url, payload, "discord"):
            sent_any = True
    
    if slack_url:
        print(f"[*] Sending Slack notification ({args.status})...")
        payload = format_slack_message(args.status, summary, args.message)
        if send_webhook(slack_url, payload, "slack"):
            sent_any = True
    
    if sent_any:
        print("[✓] Notifications complete")
        sys.exit(0)
    else:
        print("[✗] Failed to send any notifications")
        sys.exit(0)  # Don't fail workflow


if __name__ == "__main__":
    main()

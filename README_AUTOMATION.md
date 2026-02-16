# 🤖 Automated CI/CD Pipeline

## Overview

The Red Team Attack Simulator includes a complete CI/CD automation system for continuous security testing with scheduled runs, real-time notifications, and automatic dashboard deployment.

## Features

✅ **Scheduled Attack Runs** - Automated weekly security scans via GitHub Actions  
✅ **Real-Time Notifications** - Discord/Slack alerts on critical vulnerabilities  
✅ **Auto-Deploy Dashboard** - Live results at GitHub Pages  
✅ **On-Demand Testing** - Manual workflow triggers with custom parameters  
✅ **Complete History** - All attack results tracked and versioned  

## Quick Start

### 1. Setup (One-Time)

```bash
# Copy automation files to your repo
cp automated_run.py your-repo/
cp notify.py your-repo/
cp -r .github your-repo/

# Configure GitHub Secrets (Settings → Secrets → Actions)
AZURE_OPENAI_API_KEY
AZURE_OPENAI_ENDPOINT
AZURE_OPENAI_DEPLOYMENT
AZURE_OPENAI_API_VERSION
ANTHROPIC_API_KEY
DISCORD_WEBHOOK  (optional)
```

**Full setup guide:** [`AUTOMATION_SETUP.md`](AUTOMATION_SETUP.md)

### 2. Enable Automation

Push the files to your repository:
```bash
git add .github/ automated_run.py notify.py
git commit -m "feat: Add CI/CD automation pipeline"
git push origin main
```

Automation is now active! Runs every Monday at midnight UTC.

### 3. Manual Testing

Trigger a test run:
1. Go to Actions tab
2. Click "Automated Red Team Attack Run"
3. Click "Run workflow"
4. Select mode: `quick` for fast test
5. Run workflow

### 4. View Live Dashboard

After the first run, your dashboard is live at:
```
https://[username].github.io/red-team-simulator/
```

## Usage

### Execution Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `full` | All techniques × all targets | Weekly comprehensive scan |
| `quick` | 5 random attacks | Fast connectivity test |
| `category` | All techniques in a category | Focus on specific attack type |
| `chains` | Multi-turn escalation chains | Advanced persistent threats |

### Command Line

```bash
# Local testing
python automated_run.py --mode full --targets azure-openai claude

# Category scan
python automated_run.py --mode category --category PI --targets azure-openai

# Chains only
python automated_run.py --mode chains --targets claude
```

### Scheduled Runs

Edit `.github/workflows/automated-redteam.yml`:

```yaml
schedule:
  - cron: '0 0 * * 1'  # Every Monday at midnight UTC
```

## Notifications

The system sends alerts to Discord/Slack:

🟢 **Success**: No critical vulnerabilities detected  
🔴 **Critical**: High/Critical severity attacks succeeded  
🟠 **Failure**: Run encountered an error  

### Example Discord Alert

```
🚨 CRITICAL VULNERABILITIES DETECTED

3 critical severity attacks succeeded.
Total Attacks: 45
Success Rate: 15.6%
Duration: 127s

Check the Live Dashboard for details.
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│         GitHub Actions (Scheduled/Manual)       │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│   automated_run.py (Non-Interactive Runner)    │
│   • Executes attack scenarios                  │
│   • Logs results to JSON                       │
│   • Returns exit code based on findings        │
└────────────────┬────────────────────────────────┘
                 │
         ┌───────┴───────┐
         │               │
         ▼               ▼
┌──────────────┐  ┌──────────────┐
│  Dashboard   │  │ Notifications│
│  Generator   │  │   (notify.py)│
│              │  │              │
│ docs/        │  │ Discord/     │
│ index.html   │  │ Slack        │
└──────────────┘  └──────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│           GitHub Pages (Live Dashboard)         │
│   https://username.github.io/repo-name/         │
└─────────────────────────────────────────────────┘
```

## Files

```
.github/workflows/automated-redteam.yml  # CI/CD pipeline
automated_run.py                         # Non-interactive runner
notify.py                               # Notification system
AUTOMATION_SETUP.md                      # Complete setup guide
docs/index.html                          # Auto-generated dashboard
results/attack_log.json                  # Attack history
results/automated_run_summary.json       # Latest run summary
```

## Output & Artifacts

Every run produces:
- **Attack Log**: `results/attack_log.json` (full history)
- **Run Summary**: `results/automated_run_summary.json`
- **Dashboard**: `docs/index.html` (deployed to GitHub Pages)
- **Artifacts**: Uploaded to GitHub Actions (90-day retention)

## Security

- API keys stored as GitHub Secrets (never in code)
- Workflow has minimal permissions (`contents: write`)
- Results committed to repo (private or public - your choice)
- Webhook URLs kept private in secrets

## Monitoring

View automation status:
1. **Actions Tab**: See all runs, logs, and artifacts
2. **Live Dashboard**: Real-time results at GitHub Pages
3. **Notifications**: Instant alerts in Discord/Slack

## Resume Bullet Points

> *"Implemented automated CI/CD pipeline for continuous AI security testing using GitHub Actions with scheduled attack runs and real-time vulnerability notifications"*

> *"Built production-grade red team automation system with webhook integrations, automated reporting, and continuous dashboard deployment"*

> *"Designed scalable security testing infrastructure processing 40+ attack scenarios weekly with automated result aggregation and alerting"*

---

**For detailed setup instructions, see [`AUTOMATION_SETUP.md`](AUTOMATION_SETUP.md)**

# Red Team Attack Simulator - Automation Setup Guide

## 🎯 Overview

This guide will help you set up automated, scheduled red team attack runs using GitHub Actions with notifications and automatic dashboard deployment.

---

## 📋 Prerequisites

- GitHub repository for Red Team Simulator
- Azure OpenAI API access
- Anthropic Claude API access
- (Optional) Discord or Slack webhook for notifications
- GitHub Pages enabled for dashboard hosting

---

## 🔧 Step 1: Configure GitHub Secrets

Go to your repository → Settings → Secrets and variables → Actions → New repository secret

Add the following secrets:

### Required Secrets:

```
AZURE_OPENAI_API_KEY
AZURE_OPENAI_ENDPOINT
AZURE_OPENAI_DEPLOYMENT
AZURE_OPENAI_API_VERSION
ANTHROPIC_API_KEY
```

### Optional (for notifications):

```
DISCORD_WEBHOOK  (recommended)
SLACK_WEBHOOK    (alternative)
```

### How to get your API keys:

**Azure OpenAI:**
1. Go to Azure Portal → Azure OpenAI resource
2. Keys and Endpoint → Copy Key 1
3. Copy Endpoint URL
4. Note your deployment name (e.g., "gpt-4o")
5. API Version: `2024-02-15-preview` (or latest)

**Anthropic Claude:**
1. Go to https://console.anthropic.com
2. Settings → API Keys
3. Create a new key
4. Copy the key (starts with `sk-ant-`)

---

## 📢 Step 2: Setup Discord Webhook (Optional but Recommended)

### Create Discord Webhook:

1. Open Discord → Select your server
2. Right-click the channel → Edit Channel
3. Integrations → Webhooks → New Webhook
4. Name it "Red Team Bot"
5. Copy Webhook URL
6. Add to GitHub Secrets as `DISCORD_WEBHOOK`

The bot will send notifications like:
- ✅ **Success:** Run completed, no critical vulnerabilities
- 🚨 **Critical:** High/Critical severity attacks succeeded
- ❌ **Failure:** Run encountered an error

---

## 📊 Step 3: Enable GitHub Pages for Dashboard

1. Go to repository Settings → Pages
2. Source: Deploy from a branch
3. Branch: `main` (or `master`)
4. Folder: `/docs`
5. Save

Your dashboard will be live at:
```
https://[username].github.io/[repo-name]/
```

For example:
```
https://griff-reaper.github.io/red-team-simulator/
```

---

## 📁 Step 4: Add Required Files to Repository

Copy these files to your Red Team Simulator repository:

```
your-repo/
├── .github/
│   └── workflows/
│       └── automated-redteam.yml    # GitHub Actions workflow
├── automated_run.py                  # Non-interactive runner
├── notify.py                         # Notification system
├── docs/                            # Dashboard output (created automatically)
│   └── index.html                   # Auto-generated
├── results/                         # Results directory
│   ├── attack_log.json
│   └── automated_run_summary.json
└── ... (existing files)
```

---

## ⚙️ Step 5: Configure Automation Schedule

The workflow is set to run **every Monday at midnight UTC**.

To change the schedule, edit `.github/workflows/automated-redteam.yml`:

```yaml
on:
  schedule:
    - cron: '0 0 * * 1'  # Every Monday at 00:00 UTC
```

**Common schedules:**
```yaml
'0 0 * * *'      # Daily at midnight
'0 0 * * 1'      # Every Monday
'0 0 * * 1,4'    # Monday and Thursday
'0 */6 * * *'    # Every 6 hours
'0 0 1 * *'      # First day of every month
```

---

## 🚀 Step 6: Test Manual Run

Before the scheduled run, test it manually:

1. Go to repository → Actions tab
2. Click "Automated Red Team Attack Run"
3. Click "Run workflow"
4. Select options:
   - **Mode:** `quick` (for fast test)
   - **Targets:** `azure-openai claude`
5. Click "Run workflow"

Watch the logs to ensure everything works.

---

## 📈 Step 7: Verify Dashboard Deployment

After the first run:

1. Check that `docs/index.html` was created
2. Visit your GitHub Pages URL
3. Verify the dashboard displays results
4. Check that stats are updating

---

## 🔔 Step 8: Verify Notifications

If you set up Discord/Slack:

1. After a run completes, check your channel
2. You should see a notification with:
   - Run status
   - Attack statistics
   - Link to live dashboard

---

## 🎯 Usage Examples

### Manual Runs:

**Quick Test (5 random attacks):**
```yaml
Mode: quick
Targets: azure-openai claude
```

**Full Assault (all techniques):**
```yaml
Mode: full
Targets: azure-openai claude
```

**Category Sweep (e.g., Prompt Injection):**
```yaml
Mode: category
Category: PI
Targets: azure-openai claude
```

**Escalation Chains:**
```yaml
Mode: chains
Targets: claude
```

### Command Line (Local Testing):

```bash
# Quick test
python automated_run.py --mode quick --targets azure-openai claude

# Full assault
python automated_run.py --mode full --targets azure-openai claude

# Category sweep
python automated_run.py --mode category --category PI --targets azure-openai claude

# Escalation chains
python automated_run.py --mode chains --targets claude

# Generate dashboard
python generate_dashboard.py -o docs/
```

---

## 📊 Understanding Results

### Exit Codes:

- **0:** Run successful, no critical vulnerabilities
- **1:** Run successful, but CRITICAL vulnerabilities found
- **Non-zero (other):** Run failed

The workflow uses these to trigger different notifications.

### Output Files:

```
results/attack_log.json              # Full attack history
results/automated_run_summary.json   # Latest run summary
docs/index.html                      # Interactive dashboard
```

---

## 🔒 Security Best Practices

1. **Never commit `.env` files**
   - Add to `.gitignore`
   - Use GitHub Secrets only

2. **Rotate API keys regularly**
   - Update in GitHub Secrets
   - No code changes needed

3. **Review webhook URLs**
   - Ensure Discord/Slack webhooks are private
   - Don't share webhook URLs publicly

4. **Monitor API usage**
   - Check Azure/Anthropic billing
   - Adjust schedule if needed

5. **Limit workflow permissions**
   - Workflow only needs `contents: write`
   - No additional permissions required

---

## 🐛 Troubleshooting

### Workflow fails with "Authentication error":
- Check that all required secrets are set
- Verify API keys are valid and not expired
- Ensure no extra spaces in secret values

### Dashboard not updating:
- Verify GitHub Pages is enabled
- Check that `docs/` folder exists in main branch
- Wait 2-3 minutes for GitHub Pages to rebuild

### No notifications received:
- Verify Discord/Slack webhook URL is correct
- Check that webhook secret is set in GitHub
- Review workflow logs for notification errors

### "Module not found" errors:
- Dependencies are installed in workflow
- Check `.github/workflows/automated-redteam.yml`
- Verify `pip install` step includes all packages

---

## 📧 Support

For issues or questions:
- Check GitHub Actions logs (Actions tab → Click run → View logs)
- Review `results/automated_run_summary.json` for run details
- Test locally before troubleshooting CI/CD

---

## 🎉 You're Done!

Your Red Team Attack Simulator now has:
- ✅ Automated weekly security scans
- ✅ Real-time notifications on vulnerabilities
- ✅ Auto-updating live dashboard
- ✅ Complete attack history tracking
- ✅ On-demand manual testing

**Your pipeline is production-ready.** 🔥

---

## 🚀 Next Steps

1. Add this to your resume:
   > *"Implemented CI/CD pipeline for automated AI security testing using GitHub Actions with scheduled attack runs, webhook notifications, and continuous dashboard deployment"*

2. Share the live dashboard with potential employers

3. Iterate: Add more attack vectors as you discover them

---

**Built by Jace Griffith | 2026**

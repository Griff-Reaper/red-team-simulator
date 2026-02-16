# 🚀 Red Team Automation - Quick Deployment Checklist

## ✅ Pre-Deployment Checklist

- [ ] Have Azure OpenAI API credentials
- [ ] Have Anthropic Claude API key
- [ ] Have Discord webhook URL (optional but recommended)
- [ ] Repository has GitHub Pages enabled

---

## 📝 Deployment Steps (10 minutes)

### Step 1: Add Files to Repository (2 min)

```bash
# Navigate to your Red Team Simulator repo
cd path/to/red-team-simulator

# Copy automation files
cp automated_run.py .
cp notify.py .
mkdir -p .github/workflows
cp automated-redteam.yml .github/workflows/

# Commit and push
git add .github/ automated_run.py notify.py
git commit -m "feat: Add CI/CD automation pipeline"
git push origin main
```

### Step 2: Configure GitHub Secrets (3 min)

Go to: **Repository → Settings → Secrets and variables → Actions**

Click "New repository secret" and add:

```
Name: AZURE_OPENAI_API_KEY
Value: [your key]

Name: AZURE_OPENAI_ENDPOINT
Value: https://your-resource.openai.azure.com/

Name: AZURE_OPENAI_DEPLOYMENT
Value: gpt-4o

Name: AZURE_OPENAI_API_VERSION
Value: 2024-02-15-preview

Name: ANTHROPIC_API_KEY
Value: sk-ant-...

Name: DISCORD_WEBHOOK (optional)
Value: https://discord.com/api/webhooks/...
```

### Step 3: Enable GitHub Pages (2 min)

1. Go to **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: **main**
4. Folder: **/docs**
5. Click **Save**

Your dashboard will be at:
```
https://[your-username].github.io/red-team-simulator/
```

### Step 4: Test Manual Run (3 min)

1. Go to **Actions** tab
2. Click **"Automated Red Team Attack Run"**
3. Click **"Run workflow"**
4. Settings:
   - Mode: **quick**
   - Targets: **azure-openai claude**
5. Click **"Run workflow"**

Wait 2-3 minutes, then check:
- [ ] Workflow completed successfully
- [ ] `docs/index.html` was created
- [ ] Dashboard is live at GitHub Pages URL
- [ ] (If Discord setup) Notification received

---

## ✅ Post-Deployment Verification

### Check 1: Workflow Status
- [ ] Go to Actions tab → See green checkmark ✅
- [ ] Click on the run → All steps passed

### Check 2: Dashboard
- [ ] Visit `https://[username].github.io/red-team-simulator/`
- [ ] Dashboard loads and shows stats
- [ ] Attack results are visible

### Check 3: Notifications
- [ ] Discord/Slack received notification
- [ ] Notification shows correct stats
- [ ] Link to dashboard works

### Check 4: Files Created
- [ ] `results/attack_log.json` exists
- [ ] `results/automated_run_summary.json` exists
- [ ] `docs/index.html` exists

---

## 🎯 What Happens Now?

### Automated Runs:
- Runs **every Monday at midnight UTC**
- Full assault mode (all techniques × all targets)
- Results automatically committed to repo
- Dashboard auto-updates
- Notifications sent if critical vulnerabilities found

### Manual Runs:
- Go to Actions → Run workflow anytime
- Choose execution mode
- Results processed same way

---

## 🔧 Optional: Customize Schedule

Edit `.github/workflows/automated-redteam.yml`:

```yaml
schedule:
  - cron: '0 0 * * 1'  # Change this line
```

**Common options:**
```
'0 0 * * *'      # Daily at midnight UTC
'0 0 * * 1,4'    # Monday and Thursday
'0 */6 * * *'    # Every 6 hours
'0 0 1 * *'      # First of every month
```

---

## 📊 Monitoring Your System

### View Logs:
```
Actions → Click on a run → View step logs
```

### View Results:
```
https://[username].github.io/red-team-simulator/
```

### Check Notifications:
```
Discord/Slack channel
```

---

## 🐛 Common Issues

**Issue:** Workflow fails with "Authentication error"
**Fix:** Double-check all GitHub Secrets are set correctly

**Issue:** Dashboard not updating
**Fix:** Wait 2-3 minutes for GitHub Pages rebuild

**Issue:** No notifications
**Fix:** Verify Discord webhook URL is correct and set as secret

**Issue:** "Module not found" error
**Fix:** Ensure all dependencies listed in workflow YAML

---

## 🎉 Success Criteria

You're done when:
- ✅ Manual workflow run completes successfully
- ✅ Dashboard is live at GitHub Pages URL
- ✅ Notification received (if configured)
- ✅ All steps in Actions tab show green checkmarks

---

## 📝 Update Your Resume

Add these bullet points:

> *"Implemented automated CI/CD pipeline for continuous AI security testing using GitHub Actions with scheduled attack runs and real-time vulnerability notifications"*

> *"Built production-grade security automation processing 40+ attack scenarios weekly with automated reporting and webhook alerting"*

---

## 📧 Need Help?

Check the complete guide: **AUTOMATION_SETUP.md**

---

**Time to completion: ~10 minutes**
**Your automation system is now LIVE! 🔥**

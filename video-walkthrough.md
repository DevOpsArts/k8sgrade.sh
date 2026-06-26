# k8sgrade Video Walkthrough

This guide helps you record a short demo video that explains what k8sgrade does and how to run it.

## Video Goal

Show, in one pass:

- what k8sgrade checks
- how to run it in interactive and direct modes
- how to read the score and recommendations
- how to export CSV output

## Suggested Duration

4 to 6 minutes.

## Pre-Recording Checklist

1. Open a terminal in the repository root.
2. Confirm script is executable:
   - chmod +x ./k8sgrade.sh
3. Verify prerequisites are available:
   - bash
   - kubectl
4. Optional but useful:
   - python3
   - trivy
5. Keep one known context and namespace ready for a stable demo.

## Demo Script With Timeline

### 00:00 - 00:25 Intro

Voice-over:
"In this video, I will show how k8sgrade reviews Kubernetes health and security posture, calculates a score, and gives actionable fixes."

On screen:

- Show repository root
- Open README section with usage examples

Commands:

```bash
pwd
ls -1
```

### 00:25 - 01:05 What It Does

Voice-over:
"k8sgrade starts from a score of 100, checks node and pod health, workload hardening, network and disruption controls, service account and RBAC risk, and optional Trivy vulnerability signals. It then prints deductions and recommendations."

On screen:

- Scroll through README sections: Features, What the Script Checks, Score Calculation

### 01:05 - 01:50 Interactive Run

Voice-over:
"First, interactive mode. The script prompts for context and namespace, then runs all checks."

On screen:

- Run interactive command
- Select a context and namespace

Command:

```bash
./k8sgrade.sh
```

Callout:

- Mention that the script validates connectivity before running deeper checks.

### 01:50 - 02:35 Direct Non-Interactive Run

Voice-over:
"If you already know your context and namespace, run directly with c and n options for repeatable automation."

On screen:

- Run with known context and namespace

Command template:

```bash
./k8sgrade.sh -c your-context -n your-namespace
```

Optional explicit automation mode:

```bash
./k8sgrade.sh -a -c your-context -n your-namespace
```

### 02:35 - 03:20 Optional Trivy and CSV Export

Voice-over:
"For image vulnerability checks, use install-trivy if Trivy is missing. You can also export the full summary and score breakdown to CSV."

On screen:

- Run one command that includes export

Command template:

```bash
./k8sgrade.sh --install-trivy -c your-context -n your-namespace --export-csv ./k8sgrade-report.csv
```

Then show output file:

```bash
ls -lh ./k8sgrade-report.csv
head -20 ./k8sgrade-report.csv
```

### 03:20 - 04:20 How To Read Results

Voice-over:
"Review these sections in order: node and pod health, workload safety, exposure and resilience, service accounts, RBAC review, then score breakdown and recommendations. The breakdown explains each deduction, so teams can prioritize quick wins first."

On screen:

- Highlight:
  - score breakdown
  - final grade
  - recommendations

### 04:20 - 04:40 Close

Voice-over:
"Use k8sgrade in daily cluster checks, release gates, or periodic posture reviews. Start interactive for discovery, then automate with direct mode and CSV export."

On screen:

- End on final score and repo name

## Clean Demo Command Set

Use these in order during recording:

```bash
chmod +x ./k8sgrade.sh
./k8sgrade.sh
./k8sgrade.sh -c your-context -n your-namespace
./k8sgrade.sh -a -c your-context -n your-namespace
./k8sgrade.sh --install-trivy -c your-context -n your-namespace --export-csv ./k8sgrade-report.csv
```

## Recording Quality Tips

- Use a larger terminal font so tables are readable in 1080p.
- Keep terminal width wide to avoid wrapped table columns.
- Pause 2 to 3 seconds after each major section appears.
- If sensitive values are visible in context names or images, mask before publishing.

## Optional Publish Formats

- Internal demo: screen capture plus voice-over.
- Public tutorial: intro card, chapter markers, and subtitles.
- Short version: 60 to 90 seconds using only direct run plus score explanation.

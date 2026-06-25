# k8sgrade

`k8sgrade` is a Bash-based Kubernetes health and workload review script.

It connects to a selected cluster context, inspects a namespace, summarizes runtime health, and produces a score with deductions for operational and security gaps.

## Prerequisites

- `bash`
- `kubectl`
- Access to one or more Kubernetes contexts
- A valid kubeconfig, either from the default location or passed with `-k`

Optional:

- `python3`
  Used for JSON-based parsing of pod, affinity, service account, and RBAC data.
- `trivy`
  Used for critical container image vulnerability checks.

## How This Script Works

1. Validates prerequisites and input arguments.
2. Selects Kubernetes context (interactive or from command line).
3. Verifies cluster connectivity.
4. Selects namespace (interactive or from command line).
5. Collects health and security signals across nodes, pods, workload settings, services, affinity, service accounts, RBAC, and vulnerabilities.
6. Calculates score deductions from a base score of 100 and builds recommendations.
7. Prints section-wise report tables, score breakdown, final grade dashboard, and optional CSV export.

## Website

This repository includes a static project website in the `docs/` directory.

- Entry page: `docs/index.html`
- Styling: `docs/styles.css`
- Client script: `docs/script.js`

GitHub Pages deployment is configured through:

- `.github/workflows/pages.yml`

On push to `main`, GitHub Actions deploys the `docs/` folder to GitHub Pages.

## Quick Start

### Interactive mode (guided)
```bash
./k8sgrade.sh
```
The script will ask you to select a cluster context and namespace.

### Direct run (cluster name known)
```bash
./k8sgrade.sh -c devopsart-k8s -n aiops
```
Replace `devopsart-k8s` with your cluster name and `aiops` with your namespace.

### Direct run (by context number)
```bash
./k8sgrade.sh -c 3 -n aiops
```
Select the cluster by position in the context list, replace `3` with the actual number shown in the interactive selector.

## Features

- Interactive context selection from the active kubeconfig
- Context selection by name or by displayed number
- Namespace selection interactively or directly from the command line
- Non-interactive execution when cluster and namespace are already known
- Node status review with summary
- Restarted pod summary
- Top CPU and memory consumers
- Workload safety review for:
  - resource requests and limits
  - readiness and liveness probes
  - run-as-non-root posture
  - privileged containers
  - read-only root filesystem
- Exposure and resilience review for:
  - `NetworkPolicy`
  - `PodDisruptionBudget`
  - non-`ClusterIP` services
- Scheduling affinity review for:
  - node affinity
  - pod affinity
  - pod anti-affinity
- Service account inventory
- RBAC coverage summary
- Scoped service account RBAC review for service accounts actually used by pods in the selected namespace
- Critical vulnerability scan using Trivy when available
- Score breakdown with improvement suggestions
- Final overview dashboard

## Usage

```bash
./k8sgrade.sh [-a] [--install-trivy] [--export-csv /path/to/report.csv] [-k /path/to/kubeconfig] [-c context-or-number] [-n namespace]
```

## Common Use Cases

### 1. Fully interactive run

Use this when you want the script to ask for cluster context and namespace.

```bash
./k8sgrade.sh
```

### 2. Use a specific kubeconfig

```bash
./k8sgrade.sh -k ~/.kube/config
```

### 3. Run directly with cluster name and namespace

If the user already knows the cluster and namespace, the script runs without prompts.

```bash
./k8sgrade.sh -c devopsart-k8s -n aiops
```

### 4. Run directly with the context number and namespace

The `-c` option also accepts the context number shown in the interactive list.

```bash
./k8sgrade.sh -c 3 -n aiops
```

### 5. Explicit non-interactive mode

```bash
./k8sgrade.sh -a -c devopsart-k8s -n aiops
```

### 6. Automatically install Trivy if missing

```bash
./k8sgrade.sh --install-trivy -c devopsart-k8s -n aiops
```

### 7. Export final report to CSV

```bash
./k8sgrade.sh -c devopsart-k8s -n aiops --export-csv ./k8sgrade-report.csv
```

## Command-Line Options

- `-a`
  Force non-interactive mode.
- `--install-trivy`
  Install Trivy automatically if it is missing, then run the image scan.
- `--export-csv /path/to/report.csv`
  Export a CSV report with summary metrics, score breakdown, and recommendations.
- `-k /path/to/kubeconfig`
  Use a specific kubeconfig file.
- `-c context-or-number`
  Select the Kubernetes context by name or by numeric position from the context list.
- `-n namespace`
  Select the namespace directly.
- `-h`, `--help`
  Print usage help.

## What the Script Checks

### Cluster and Node Health

- selected cluster connectivity
- node readiness
- node count summary
- cluster CPU and memory usage percentage

### Pod Health

- pending pod count
- restart counts
- top CPU consumers
- top memory consumers

### Workload Safety

- missing CPU or memory requests and limits
- missing readiness or liveness probes
- containers that appear to run as root
- privileged containers
- containers without read-only root filesystem

### Exposure and Resilience

- missing `NetworkPolicy`
- missing `PodDisruptionBudget`
- services using types other than `ClusterIP`

### Scheduling Affinity

- missing node affinity
- missing pod affinity
- missing pod anti-affinity

### Service Accounts

- which service account each pod uses
- whether pods use the `default` service account
- whether `automountServiceAccountToken` is set, unset, or disabled

### RBAC Coverage

- namespace `Role` count
- namespace `RoleBinding` count
- cluster-wide `ClusterRoleBinding` entries and service account subjects

### Scoped Service Account RBAC Review

For service accounts used by pods in the selected namespace, the script reviews:

- number of namespace `RoleBinding` attachments
- number of `ClusterRoleBinding` attachments
- whether cluster-wide scope is used
- whether wildcard permissions appear in bound rules
- whether `cluster-admin` is present
- whether rules can read or modify Kubernetes secrets

### Vulnerability Review

- critical image findings through Trivy

## Score Calculation

The script starts from `100` and subtracts penalties.

Current penalty areas include:

- node readiness
- pending pods
- pod restarts
- missing resource requests or limits
- missing probes
- root-user risk
- privileged containers
- writable root filesystem
- missing `NetworkPolicy`
- missing `PodDisruptionBudget`
- exposed services
- missing affinity rules
- default service account usage
- missing namespace `RoleBinding`
- cluster-scope service account bindings
- high-risk RBAC rules
- secret-access RBAC
- CPU pressure
- memory pressure
- critical vulnerabilities

The report prints a score breakdown table so you can see each deduction.

## Output Sections

Typical output includes:

- Kubernetes cluster status
- cluster connectivity
- node status
- restarted pods
- top CPU consumers
- top memory consumers
- workload safety scope
- exposure and resilience
- critical vulnerability check
- service accounts
- RBAC coverage
- service account RBAC review
- scheduling affinity
- score breakdown
- improvement suggestions
- final overview

## Important Behavior Notes

- If both `-c` and `-n` are provided, the script runs without prompting the user.
- If `-c` is numeric, the script resolves it against the current kube context list.
- If Trivy is not installed and `--install-trivy` is not used, vulnerability scanning is skipped.
- Some JSON-backed sections depend on `python3`. If it is missing, those sections may be skipped.

## Current RBAC Limitation

The script now evaluates whether used service accounts have risky or broad bindings, but it still does not prove that a workload has exactly the permissions it needs for all of its application actions.

In other words, it can identify risky patterns such as:

- no namespace `RoleBinding`
- cluster-scoped binding usage
- wildcard permissions
- `cluster-admin`
- secrets access

But it does not yet perform a workload-specific authorization baseline such as:

- `kubectl auth can-i --as system:serviceaccount:<namespace>:<serviceaccount> ...`
- exact permission matching to application behavior

## Example Commands

```bash
./k8sgrade.sh
./k8sgrade.sh -k ~/.kube/config
./k8sgrade.sh -c devopsart-k8s -n aiops
./k8sgrade.sh -c 3 -n aiops
./k8sgrade.sh -a -c devopsart-k8s -n aiops
./k8sgrade.sh --install-trivy -c devopsart-k8s -n aiops
./k8sgrade.sh -c devopsart-k8s -n aiops --export-csv ./k8sgrade-report.csv
```

## Exit Behavior

The script exits with an error when:

- `kubectl` is missing
- no contexts are available
- the kubeconfig path is invalid
- the requested context does not exist
- the requested namespace does not exist
- non-interactive execution is requested without enough input

## File Layout

- `k8sgrade.sh`: main script
- `README.md`: feature and usage documentation
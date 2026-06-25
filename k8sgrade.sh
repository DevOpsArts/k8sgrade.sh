#!/usr/bin/env bash
# If invoked via `sh k8sgrade.sh`, re-exec with bash before parsing bash-only syntax.
if [ -z "${BASH_VERSION:-}" ] || [ "${BASH##*/}" = "sh" ]; then
  exec bash "$0" "$@"
fi

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
APP_NAME="k8sgrade"

usage() {
  cat <<'EOF'
Usage:
  k8sgrade.sh [-a] [--install-trivy] [--export-csv /path/to/report.csv] [-k /path/to/kubeconfig] [-c context-or-number] [-n namespace]

What it does:
  1. Lists configured kube contexts from the active kubeconfig or the one you pass
  2. Lets you select the Kubernetes context to inspect
  3. Checks node status
  4. Prompts for a namespace if not provided
  5. Shows restarted pods, pod age, top 10 CPU and memory consumers
  6. Adds a neutral workload safety scope for resources, probes, and container hardening
  7. Attempts a basic critical vulnerability check if trivy is installed
  8. Prints a simple cluster health score
  9. In non-interactive mode (-a), or when both -c and -n are provided, it uses the supplied context/namespace and exits with an error if they are missing
  10. With --install-trivy, it installs Trivy automatically if it is missing and then runs the vulnerability scan

Examples:
  k8sgrade.sh
  k8sgrade.sh -k ~/.kube/config
  k8sgrade.sh -c prod-context -n aiops
  k8sgrade.sh -c 3 -n aiops
  k8sgrade.sh -c devopsart-k8s -n aiops
  k8sgrade.sh -a -c prod-context -n aiops
  k8sgrade.sh --install-trivy -c prod-context -n aiops
  k8sgrade.sh -c prod-context -n aiops --export-csv ./k8sgrade-report.csv
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 1
  fi
}

check_prerequisites() {
  local -a required_cmds=(kubectl awk grep sort head)
  local -a missing_cmds=()
  local cmd=""

  for cmd in "${required_cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_cmds+=("$cmd")
    fi
  done

  if [[ ${#missing_cmds[@]} -gt 0 ]]; then
    echo "ERROR: prerequisite check failed. Missing command(s): ${missing_cmds[*]}" >&2
    exit 1
  fi

  # python3 and trivy remain optional; warn early so users know some sections may be skipped.
  if ! command -v python3 >/dev/null 2>&1; then
    echo "WARNING: optional prerequisite not found: python3 (some JSON-backed checks may be skipped)" >&2
  fi

  if ! command -v trivy >/dev/null 2>&1; then
    echo "WARNING: optional prerequisite not found: trivy (image vulnerability scan may be skipped)" >&2
  fi
}

pick_from_list() {
  local prompt="$1"
  shift
  local -a items=("$@")
  local index choice

  if [[ ${#items[@]} -eq 0 ]]; then
    echo "ERROR: no items available for selection" >&2
    exit 1
  fi

  if [[ ${#items[@]} -eq 1 ]]; then
    echo "${items[0]}"
    return 0
  fi

  printf '%s\n' "$prompt" >&2
  for index in "${!items[@]}"; do
    printf '  %2d) %s\n' "$((index + 1))" "${items[$index]}" >&2
  done

  while true; do
    printf 'Select a number [1-%d]: ' "${#items[@]}" >&2
    read -r choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#items[@]} )); then
      echo "${items[$((choice - 1))]}"
      return 0
    fi
    printf '%s\n' "Invalid selection, try again." >&2
  done
}

resolve_context_selection() {
  local selection="$1"
  shift
  local -a contexts=("$@")

  if [[ "$selection" =~ ^[0-9]+$ ]]; then
    if (( selection >= 1 && selection <= ${#contexts[@]} )); then
      printf '%s' "${contexts[$((selection - 1))]}"
      return 0
    fi
    echo "ERROR: context number out of range: $selection" >&2
    return 1
  fi

  if printf '%s\n' "${contexts[@]}" | grep -Fxq "$selection"; then
    printf '%s' "$selection"
    return 0
  fi

  echo "ERROR: context not found: $selection" >&2
  return 1
}

is_safe_context_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9._:@/-]+$ ]]
}

is_safe_namespace_name() {
  local value="$1"
  [[ "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]
}

trim() {
  local value="$1"
  value="${value#${value%%[![:space:]]*}}"
  value="${value%${value##*[![:space:]]}}"
  printf '%s' "$value"
}

bytes_to_human() {
  local bytes="${1:-0}"
  # SECURITY_NOTE: Quote variable passed to awk to prevent injection
  awk -v b="${bytes}" 'BEGIN {
    split("B Ki Mi Gi Ti Pi", u, " ");
    i = 1;
    while (b >= 1024 && i < 6) { b /= 1024; i++; }
    printf "%.2f%s", b, u[i]
  }'
}

parse_quantity_to_mib() {
  local value="${1:-0}"
  # SECURITY_NOTE: Quote variable passed to awk to prevent injection
  awk -v v="${value}" 'BEGIN {
    if (v == "" || v == "<none>") { print 0; exit }
    if (v ~ /Mi$/) { sub(/Mi$/, "", v); print v + 0; exit }
    if (v ~ /Gi$/) { sub(/Gi$/, "", v); printf "%.0f", (v + 0) * 1024; exit }
    if (v ~ /Ki$/) { sub(/Ki$/, "", v); printf "%.0f", (v + 0) / 1024; exit }
    if (v ~ /m$/) { sub(/m$/, "", v); print v + 0; exit }
    print v + 0
  }'
}

parse_quantity_to_mcpu() {
  local value="${1:-0}"
  # SECURITY_NOTE: Quote variable passed to awk to prevent injection
  awk -v v="${value}" 'BEGIN {
    if (v == "" || v == "<none>") { print 0; exit }
    if (v ~ /m$/) { sub(/m$/, "", v); print v + 0; exit }
    printf "%.0f", (v + 0) * 1000
  }'
}

as_percent() {
  local used="$1"
  local total="$2"
  # SECURITY_NOTE: Quote variables passed to awk to prevent injection
  awk -v u="${used}" -v t="${total}" 'BEGIN { if (t <= 0) { print 0; exit } printf "%.0f", (u / t) * 100 }'
}

csv_escape() {
  local value="${1:-}"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

csv_write_row() {
  local output_file="$1"
  shift
  local first=1
  local field=""

  {
    for field in "$@"; do
      if (( first )); then
        first=0
      else
        printf ','
      fi
      csv_escape "$field"
    done
    printf '\n'
  } >> "$output_file"
}

export_report_csv() {
  local output_file="$1"
  local output_dir=""
  local row=""
  local factor=""
  local impact=""
  local detail=""
  local action=""
  local reason=""

  output_dir="$(dirname "$output_file")"
  if [[ ! -d "$output_dir" ]]; then
    mkdir -p "$output_dir" || {
      echo "ERROR: unable to create export directory: $output_dir" >&2
      return 1
    }
  fi

  : > "$output_file" || {
    echo "ERROR: unable to write export file: $output_file" >&2
    return 1
  }

  csv_write_row "$output_file" "section" "key" "value" "detail"

  csv_write_row "$output_file" "summary" "context" "$SELECTED_CONTEXT" ""
  csv_write_row "$output_file" "summary" "namespace" "$SELECTED_NAMESPACE" ""
  csv_write_row "$output_file" "summary" "score" "$SCORE" "out of 100"
  csv_write_row "$output_file" "summary" "total_deductions" "$SCORE_PENALTY_TOTAL" ""
  csv_write_row "$output_file" "summary" "grade" "$GRADE" "$GRADE_LABEL"
  csv_write_row "$output_file" "summary" "nodes_total" "$TOTAL_NODES" ""
  csv_write_row "$output_file" "summary" "nodes_not_ready" "$NOT_READY_NODES" ""
  csv_write_row "$output_file" "summary" "pending_pods" "$PENDING_PODS" ""
  csv_write_row "$output_file" "summary" "total_restarts" "$TOTAL_RESTARTS" ""
  csv_write_row "$output_file" "summary" "cpu_usage_pct" "$CPU_USAGE_PCT" ""
  csv_write_row "$output_file" "summary" "memory_usage_pct" "$MEM_USAGE_PCT" ""
  csv_write_row "$output_file" "summary" "critical_image_signals" "$CRIT_VULNS" ""

  if [[ ${#SCORE_BREAKDOWN_ROWS[@]} -gt 0 ]]; then
    for row in "${SCORE_BREAKDOWN_ROWS[@]}"; do
      IFS='|' read -r factor impact detail <<< "$row"
      csv_write_row "$output_file" "score_breakdown" "$factor" "$impact" "$detail"
    done
  fi

  if [[ ${#RECOMMENDATION_ROWS[@]} -gt 0 ]]; then
    for row in "${RECOMMENDATION_ROWS[@]}"; do
      IFS='|' read -r action reason <<< "$row"
      csv_write_row "$output_file" "recommendation" "$action" "" "$reason"
    done
  fi
}

prompt_yes_no() {
  local prompt="$1"
  local answer
  local answer_lower
  while true; do
    printf '%s [y/n]: ' "$prompt" >&2
    read -r answer
    answer_lower="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
    case "$answer_lower" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) printf '%s\n' "Please answer y or n." >&2 ;;
    esac
  done
}

install_trivy() {
  local install_dir="${TRIVY_INSTALL_DIR:-$HOME/.local/bin}"
  local install_script=""
  local dir_mode=""
  local dir_mode_int=0

  if command -v brew >/dev/null 2>&1; then
    echo "Installing Trivy with Homebrew..."
    if brew install trivy >/dev/null 2>&1; then
      return 0
    fi
    echo "Homebrew install failed; falling back to direct Trivy binary install." >&2
  fi

  if command -v curl >/dev/null 2>&1; then
    if [[ -d "$install_dir" ]]; then
      if [[ ! -w "$install_dir" ]]; then
        echo "ERROR: install directory is not writable: $install_dir" >&2
        return 1
      fi
    else
      # SECURITY_NOTE: Create installation directory with least-privilege permissions.
      mkdir -p -m 0755 "$install_dir"
    fi

    dir_mode="$(stat -f '%Lp' "$install_dir" 2>/dev/null || stat -c '%a' "$install_dir" 2>/dev/null || printf '755')"
    if [[ "$dir_mode" =~ ^[0-7]{3,4}$ ]]; then
      dir_mode_int=$((8#$dir_mode))
      if (( (dir_mode_int & 2) != 0 )); then
        echo "ERROR: install directory is world-writable: $install_dir" >&2
        return 1
      fi
    fi

    install_script="$(mktemp /tmp/trivy-install.XXXXXX.sh)"
    echo "Installing Trivy from the official release script into ${install_dir}..."
    if curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -o "$install_script"; then
      # SECURITY_NOTE: Validate script integrity before execution.
      if ! head -n 1 "$install_script" | grep -q '^#!/'; then
        echo "ERROR: downloaded Trivy install script failed validation." >&2
        rm -f "$install_script"
        return 1
      fi
      if [[ -n "${TRIVY_INSTALL_SCRIPT_SHA256:-}" ]]; then
        local script_hash=""
        script_hash="$(shasum -a 256 "$install_script" | awk '{print $1}')"
        if [[ "$script_hash" != "$TRIVY_INSTALL_SCRIPT_SHA256" ]]; then
          echo "ERROR: downloaded Trivy install script checksum mismatch." >&2
          rm -f "$install_script"
          return 1
        fi
      elif ! grep -q 'github.com/aquasecurity/trivy' "$install_script"; then
        echo "ERROR: downloaded Trivy install script failed provenance validation." >&2
        rm -f "$install_script"
        return 1
      fi
      sh "$install_script" -b "$install_dir" >/dev/null 2>&1 || {
        echo "Trivy install script failed." >&2
        rm -f "$install_script"
        return 1
      }
      rm -f "$install_script"
      case ":$PATH:" in
        *":$install_dir:"*) : ;;
        *) export PATH="$install_dir:$PATH" ;;
      esac
      return 0
    fi
    echo "Unable to download Trivy install script." >&2
    rm -f "$install_script"
    return 1
  fi

  if command -v apt-get >/dev/null 2>&1; then
    echo "Installing Trivy with apt-get..."
    sudo apt-get update && sudo apt-get install -y trivy
    return 0
  fi

  if command -v dnf >/dev/null 2>&1; then
    echo "Installing Trivy with dnf..."
    sudo dnf install -y trivy
    return 0
  fi

  if command -v yum >/dev/null 2>&1; then
    echo "Installing Trivy with yum..."
    sudo yum install -y trivy
    return 0
  fi

  echo "No supported package manager found for automatic Trivy install." >&2
  return 1
}

print_boxed_table() {
  local title="$1"
  # SECURITY_NOTE: Quote variable passed to awk to prevent injection
  awk -F'|' -v title="${title}" '
    function repeat(ch, count,    out, i) {
      out = ""
      for (i = 0; i < count; i++) out = out ch
      return out
    }
    function trim(value) {
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      return value
    }
    function line(width,    out) {
      out = "+"
      out = out repeat("-", width + 2) "+"
      return out
    }
    {
      for (i = 1; i <= NF; i++) {
        cell = trim($i)
        rows[NR, i] = cell
        if (length(cell) > widths[i]) widths[i] = length(cell)
      }
      if (NF > cols) cols = NF
      if (NR == 1 && length(title) > title_width) title_width = length(title)
    }
    END {
      total_width = 0
      for (i = 1; i <= cols; i++) total_width += widths[i] + 3
      if (total_width < title_width + 4) total_width = title_width + 4

      print line(total_width - 2)
      printf("| %-*s |\n", total_width - 4, title)
      print line(total_width - 2)

      for (r = 1; r <= NR; r++) {
        row_text = ""
        for (c = 1; c <= cols; c++) {
          value = rows[r, c]
          if (value == "") value = ""
          row_text = row_text sprintf("%-*s", widths[c], value)
          if (c < cols) row_text = row_text " | "
        }
        printf("| %-*s |\n", total_width - 4, row_text)
        if (r == 1) print line(total_width - 2)
      }

      print line(total_width - 2)
    }
  '
}

supports_color() {
  [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]
}

print_grade_dashboard() {
  local selected_context="$1"
  local selected_namespace="$2"
  local score="$3"
  local penalty_total="$4"
  local grade="$5"
  local grade_label="$6"
  local total_nodes="$7"
  local not_ready_nodes="$8"
  local pending_pods="$9"
  local total_restarts="${10}"
  local cpu_pct="${11}"
  local mem_pct="${12}"
  local crit_vulns="${13}"

  local c_reset=""
  local c_title=""
  local c_label=""
  local c_value=""
  local c_ok=""
  local c_warn=""
  local c_bad=""
  local grade_color=""

  if supports_color; then
    c_reset="$(tput sgr0)"
    c_title="$(tput bold)$(tput setaf 6)"
    c_label="$(tput bold)$(tput setaf 4)"
    c_value="$(tput setaf 0 2>/dev/null || printf '')"
    c_ok="$(tput setaf 2)"
    c_warn="$(tput setaf 3)"
    c_bad="$(tput setaf 1)"
  fi

  if (( score >= 85 )); then
    grade_color="$c_ok"
  elif (( score >= 70 )); then
    grade_color="$c_warn"
  else
    grade_color="$c_bad"
  fi

  local node_health="${not_ready_nodes} not ready"
  if (( not_ready_nodes == 0 )); then
    node_health="all ready"
  fi

  local -a info_lines
  info_lines=(
    "${c_label}Context:${c_reset} ${c_value}${selected_context}${c_reset}"
    "${c_label}Namespace:${c_reset} ${c_value}${selected_namespace}${c_reset}"
    "${c_label}Score:${c_reset} ${grade_color}${score}/100${c_reset} ${c_value}(deductions ${penalty_total})${c_reset}"
    "${c_label}Grade:${c_reset} ${grade_color}${grade}${c_reset} ${c_value}- ${grade_label}${c_reset}"
    "${c_label}Nodes:${c_reset} ${c_value}${total_nodes} total, ${node_health}${c_reset}"
    "${c_label}Pods:${c_reset} ${c_value}${pending_pods} pending, ${total_restarts} restarts${c_reset}"
    "${c_label}Usage:${c_reset} ${c_value}CPU ${cpu_pct}% | MEM ${mem_pct}%${c_reset}"
    "${c_label}Vulns:${c_reset} ${c_value}${crit_vulns} critical image signal(s)${c_reset}"
  )

  printf '\n%s%s%s\n' "$c_title" "== ${APP_NAME} Overview ==" "$c_reset"
  for line in "${info_lines[@]}"; do
    printf '%s\n' "$line"
  done

  if supports_color; then
    printf '%b%b%b%b%b%b%b%b%b%b\n' "$c_bad" "####" "$c_warn" "####" "$c_ok" "####" "$c_label" "####" "$c_value" "####" "$c_reset"
  else
    printf '%s\n' "[####][####][####][####][####]"
  fi
}

collect_container_policy_rows() {
  local namespace="$1"
  local pod_json=""

  pod_json="$(kubectl get pods -n "$namespace" -o json 2>/dev/null || true)"
  if [[ -z "$pod_json" || ! -x "$(command -v python3 2>/dev/null || true)" ]]; then
    return 0
  fi

  printf '%s' "$pod_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for pod in data.get("items", []):
    pod_name = pod.get("metadata", {}).get("name", "")
    spec = pod.get("spec", {}) or {}
    for container in spec.get("containers", []):
        resources = container.get("resources", {}) or {}
        requests = resources.get("requests", {}) or {}
        limits = resources.get("limits", {}) or {}
        security = container.get("securityContext", {}) or {}

        def norm(value):
            if value is True:
                return "true"
            if value is False:
                return "false"
            if value is None:
                return ""
            return str(value)

        print("|".join([
            pod_name,
            str(container.get("name", "")),
            norm(requests.get("cpu")),
            norm(requests.get("memory")),
            norm(limits.get("cpu")),
            norm(limits.get("memory")),
            "yes" if container.get("readinessProbe") is not None else "no",
            "yes" if container.get("livenessProbe") is not None else "no",
            norm(security.get("runAsNonRoot")),
            norm(security.get("runAsUser")),
            norm(security.get("privileged")),
            norm(security.get("readOnlyRootFilesystem")),
        ]))
'
}

collect_affinity_rows() {
  local namespace="$1"
  local pod_json=""

  pod_json="$(kubectl get pods -n "$namespace" -o json 2>/dev/null || true)"
  if [[ -z "$pod_json" || ! -x "$(command -v python3 2>/dev/null || true)" ]]; then
    return 0
  fi

  printf '%s' "$pod_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for pod in data.get("items", []):
    meta = pod.get("metadata", {}) or {}
    spec = pod.get("spec", {}) or {}
    affinity = spec.get("affinity", {}) or {}
    pod_aff = affinity.get("podAffinity", {}) or {}
    pod_anti = affinity.get("podAntiAffinity", {}) or {}
    node_aff = affinity.get("nodeAffinity", {}) or {}

    def yes_no(value):
        return "yes" if value else "no"

    required_node = node_aff.get("requiredDuringSchedulingIgnoredDuringExecution")
    preferred_node = node_aff.get("preferredDuringSchedulingIgnoredDuringExecution")
    required_pod = pod_aff.get("requiredDuringSchedulingIgnoredDuringExecution")
    preferred_pod = pod_aff.get("preferredDuringSchedulingIgnoredDuringExecution")
    required_anti = pod_anti.get("requiredDuringSchedulingIgnoredDuringExecution")
    preferred_anti = pod_anti.get("preferredDuringSchedulingIgnoredDuringExecution")

    print("|".join([
        str(meta.get("name", "")),
        yes_no(bool(required_node or preferred_node)),
        yes_no(bool(required_pod or preferred_pod)),
        yes_no(bool(required_anti or preferred_anti)),
        yes_no(bool(required_node)),
        yes_no(bool(required_pod)),
        yes_no(bool(required_anti)),
    ]))
'
}

collect_service_account_rows() {
  local namespace="$1"
  local pod_json=""

  pod_json="$(kubectl get pods -n "$namespace" -o json 2>/dev/null || true)"
  if [[ -z "$pod_json" || ! -x "$(command -v python3 2>/dev/null || true)" ]]; then
    return 0
  fi

  printf '%s' "$pod_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for pod in data.get("items", []):
    meta = pod.get("metadata", {}) or {}
    spec = pod.get("spec", {}) or {}
    sa = spec.get("serviceAccountName") or "default"
    automount = spec.get("automountServiceAccountToken")
    automount_val = "unset" if automount is None else ("true" if automount else "false")
    print("|".join([
        str(meta.get("name", "")),
        str(sa),
        automount_val,
        "yes" if sa == "default" else "no",
    ]))
'
}

collect_rbac_rows() {
  local namespace="$1"
  local roles_json=""
  local rolebindings_json=""
  local clusterrolebindings_json=""

  roles_json="$(kubectl get roles -n "$namespace" -o json 2>/dev/null || true)"
  rolebindings_json="$(kubectl get rolebindings -n "$namespace" -o json 2>/dev/null || true)"
  clusterrolebindings_json="$(kubectl get clusterrolebindings -o json 2>/dev/null || true)"

  if [[ -z "$roles_json$rolebindings_json$clusterrolebindings_json" || ! -x "$(command -v python3 2>/dev/null || true)" ]]; then
    return 0
  fi

  {
    printf '%s' "$roles_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for item in data.get("items", []):
    meta = item.get("metadata", {}) or {}
    rules = item.get("rules", []) or []
    verb_count = sum(len(rule.get("verbs", []) or []) for rule in rules)
    print("role|{}|{}|{}".format(meta.get("name", ""), len(rules), verb_count))
'
    printf '%s' "$rolebindings_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for item in data.get("items", []):
    meta = item.get("metadata", {}) or {}
    subjects = item.get("subjects", []) or []
    print("rolebinding|{}|{}|{}".format(meta.get("name", ""), item.get("roleRef", {}).get("kind", ""), len(subjects)))
'
    printf '%s' "$clusterrolebindings_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for item in data.get("items", []):
    meta = item.get("metadata", {}) or {}
    subjects = item.get("subjects", []) or []
    sa_subjects = 0
    for subject in subjects:
        if subject.get("kind") == "ServiceAccount":
            sa_subjects += 1
    print("clusterrolebinding|{}|{}|{}".format(meta.get("name", ""), item.get("roleRef", {}).get("kind", ""), sa_subjects))
'
  }
}

collect_service_account_rbac_rows() {
  local namespace="$1"
  local pod_json=""
  local roles_json=""
  local clusterroles_json=""
  local rolebindings_json=""
  local clusterrolebindings_json=""

  pod_json="$(kubectl get pods -n "$namespace" -o json 2>/dev/null || true)"
  roles_json="$(kubectl get roles -n "$namespace" -o json 2>/dev/null || true)"
  clusterroles_json="$(kubectl get clusterroles -o json 2>/dev/null || true)"
  rolebindings_json="$(kubectl get rolebindings -n "$namespace" -o json 2>/dev/null || true)"
  clusterrolebindings_json="$(kubectl get clusterrolebindings -o json 2>/dev/null || true)"

  if [[ -z "$pod_json$roles_json$clusterroles_json$rolebindings_json$clusterrolebindings_json" || ! -x "$(command -v python3 2>/dev/null || true)" ]]; then
    return 0
  fi

  K8SGRADE_NAMESPACE="$namespace" \
  K8SGRADE_PODS_JSON="$pod_json" \
  K8SGRADE_ROLES_JSON="$roles_json" \
  K8SGRADE_CLUSTERROLES_JSON="$clusterroles_json" \
  K8SGRADE_ROLEBINDINGS_JSON="$rolebindings_json" \
  K8SGRADE_CLUSTERROLEBINDINGS_JSON="$clusterrolebindings_json" \
  python3 -c '
import json
import os

namespace = os.environ["K8SGRADE_NAMESPACE"]
pods = json.loads(os.environ["K8SGRADE_PODS_JSON"])
roles = json.loads(os.environ["K8SGRADE_ROLES_JSON"])
clusterroles = json.loads(os.environ["K8SGRADE_CLUSTERROLES_JSON"])
rolebindings = json.loads(os.environ["K8SGRADE_ROLEBINDINGS_JSON"])
clusterrolebindings = json.loads(os.environ["K8SGRADE_CLUSTERROLEBINDINGS_JSON"])

sa_to_pods = {}
for pod in pods.get("items", []):
    spec = pod.get("spec", {}) or {}
    sa_name = spec.get("serviceAccountName") or "default"
    sa_to_pods.setdefault(sa_name, []).append(pod.get("metadata", {}).get("name", ""))

role_rules = {}
for item in roles.get("items", []):
    role_rules[("Role", item.get("metadata", {}).get("name", ""))] = item.get("rules", []) or []

clusterrole_rules = {}
for item in clusterroles.get("items", []):
    clusterrole_rules[item.get("metadata", {}).get("name", "")] = item.get("rules", []) or []

reviews = {}
for sa_name, pod_names in sa_to_pods.items():
    reviews[sa_name] = {
        "pod_count": len(pod_names),
        "namespace_bindings": 0,
        "cluster_bindings": 0,
        "cluster_admin": False,
        "wildcard": False,
        "secrets_access": False,
        "findings": [],
    }

def mark_finding(review, finding):
    if finding not in review["findings"]:
        review["findings"].append(finding)

def apply_rules(review, rules):
    for rule in rules:
        verbs = set(rule.get("verbs", []) or [])
        resources = set(rule.get("resources", []) or [])
        api_groups = set(rule.get("apiGroups", []) or [])
        non_resource_urls = set(rule.get("nonResourceURLs", []) or [])

        if "*" in verbs or "*" in resources or "*" in api_groups or "*" in non_resource_urls:
            review["wildcard"] = True
            mark_finding(review, "wildcard-rules")

        if "*" in resources or "secrets" in resources:
            if verbs.intersection({"*", "get", "list", "watch", "create", "update", "patch", "delete"}):
                review["secrets_access"] = True
                mark_finding(review, "secrets-access")

for item in rolebindings.get("items", []):
    subjects = item.get("subjects", []) or []
    role_ref = item.get("roleRef", {}) or {}
    role_kind = role_ref.get("kind", "")
    role_name = role_ref.get("name", "")
    if role_kind == "Role":
        rules = role_rules.get(("Role", role_name), [])
    else:
        rules = clusterrole_rules.get(role_name, [])

    for subject in subjects:
        if subject.get("kind") != "ServiceAccount":
            continue
        subject_namespace = subject.get("namespace") or namespace
        subject_name = subject.get("name", "")
        if subject_namespace != namespace or subject_name not in reviews:
            continue
        review = reviews[subject_name]
        review["namespace_bindings"] += 1
        if role_kind == "ClusterRole" and role_name == "cluster-admin":
            review["cluster_admin"] = True
            mark_finding(review, "cluster-admin")
        apply_rules(review, rules)

for item in clusterrolebindings.get("items", []):
    subjects = item.get("subjects", []) or []
    role_ref = item.get("roleRef", {}) or {}
    role_name = role_ref.get("name", "")
    rules = clusterrole_rules.get(role_name, [])

    for subject in subjects:
        if subject.get("kind") != "ServiceAccount":
            continue
        subject_namespace = subject.get("namespace") or ""
        subject_name = subject.get("name", "")
        if subject_namespace != namespace or subject_name not in reviews:
            continue
        review = reviews[subject_name]
        review["cluster_bindings"] += 1
        mark_finding(review, "cluster-scope-binding")
        if role_name == "cluster-admin":
            review["cluster_admin"] = True
            mark_finding(review, "cluster-admin")
        apply_rules(review, rules)

for sa_name in sorted(reviews):
    review = reviews[sa_name]
    if review["namespace_bindings"] == 0 and review["cluster_bindings"] == 0:
        mark_finding(review, "no-bindings")

    if review["cluster_admin"] or review["wildcard"]:
        risk = "high"
    elif review["cluster_bindings"] > 0 or review["secrets_access"]:
        risk = "medium"
    elif review["namespace_bindings"] == 0:
        risk = "low"
    else:
        risk = "ok"

    findings = ",".join(review["findings"]) if review["findings"] else "scoped"
    print("|".join([
        sa_name,
        str(review["pod_count"]),
        str(review["namespace_bindings"]),
        str(review["cluster_bindings"]),
        risk,
        findings,
    ]))
  '
  }

add_recommendation() {
  local action="$1"
  local reason="$2"

  RECOMMENDATION_ROWS+=("${action}|${reason}")
}

add_score_deduction() {
  local label="$1"
  local value="$2"
  local detail="$3"

  if (( value > 0 )); then
    SCORE_BREAKDOWN_ROWS+=("${label}|-${value}|${detail}")
    SCORE_PENALTY_TOTAL=$((SCORE_PENALTY_TOTAL + value))
  fi
}

KUBECONFIG_FILE=""
SELECTED_CONTEXT=""
SELECTED_NAMESPACE=""
NON_INTERACTIVE=0
INSTALL_TRIVY_AUTO=0
EXPORT_CSV_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a)
      NON_INTERACTIVE=1
      shift
      ;;
    --install-trivy)
      INSTALL_TRIVY_AUTO=1
      shift
      ;;
    --export-csv)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: option --export-csv requires an argument" >&2
        usage
        exit 1
      fi
      EXPORT_CSV_FILE="$2"
      shift 2
      ;;
    -k)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: option -k requires an argument" >&2
        usage
        exit 1
      fi
      KUBECONFIG_FILE="$2"
      shift 2
      ;;
    -c)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: option -c requires an argument" >&2
        usage
        exit 1
      fi
      SELECTED_CONTEXT="$2"
      shift 2
      ;;
    -n)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: option -n requires an argument" >&2
        usage
        exit 1
      fi
      SELECTED_NAMESPACE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "ERROR: unknown option or argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

check_prerequisites

if [[ -n "$KUBECONFIG_FILE" ]]; then
  if [[ ! -f "$KUBECONFIG_FILE" ]]; then
    echo "ERROR: kubeconfig file not found: $KUBECONFIG_FILE" >&2
    exit 1
  fi
  # SECURITY_NOTE: Validate kubeconfig is a regular file and readable.
  if [[ ! -f "$KUBECONFIG_FILE" || -L "$KUBECONFIG_FILE" ]]; then
    echo "ERROR: kubeconfig must be a regular non-symlink file: $KUBECONFIG_FILE" >&2
    exit 1
  fi
  if [[ ! -r "$KUBECONFIG_FILE" ]]; then
    echo "ERROR: kubeconfig file not readable: $KUBECONFIG_FILE" >&2
    exit 1
  fi

  # SECURITY_NOTE: Ensure kubeconfig is parseable YAML by kubectl.
  if ! kubectl config view --kubeconfig "$KUBECONFIG_FILE" >/dev/null 2>&1; then
    echo "ERROR: kubeconfig file is not valid/parseable YAML: $KUBECONFIG_FILE" >&2
    exit 1
  fi
  export KUBECONFIG="$KUBECONFIG_FILE"
fi

if [[ -n "$SELECTED_CONTEXT" && -n "$SELECTED_NAMESPACE" ]]; then
  NON_INTERACTIVE=1
fi

echo "== Kubernetes Cluster Status =="

CONTEXTS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && CONTEXTS+=("$line")
done < <(kubectl config get-contexts -o name 2>/dev/null || true)
if [[ ${#CONTEXTS[@]} -eq 0 ]]; then
  echo "ERROR: no kubectl contexts found. Provide -k /path/to/kubeconfig or configure kubectl first." >&2
  exit 1
fi

if [[ -z "$SELECTED_CONTEXT" ]]; then
  if (( NON_INTERACTIVE )); then
    SELECTED_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
    if [[ -z "$SELECTED_CONTEXT" ]]; then
      echo "ERROR: non-interactive mode needs -c <context> or a current kubectl context." >&2
      exit 1
    fi
  else
    SELECTED_CONTEXT="$(pick_from_list 'Available kube contexts:' "${CONTEXTS[@]}")"
  fi
else
  SELECTED_CONTEXT="$(resolve_context_selection "$SELECTED_CONTEXT" "${CONTEXTS[@]}")" || exit 1
fi

if ! is_safe_context_name "$SELECTED_CONTEXT"; then
  echo "ERROR: context contains unsafe characters: $SELECTED_CONTEXT" >&2
  exit 1
fi

kubectl config use-context "$SELECTED_CONTEXT" >/dev/null
echo "Selected context: $SELECTED_CONTEXT"

echo
echo "== Cluster Connectivity =="
if kubectl cluster-info >/dev/null 2>&1; then
  echo "Cluster connection: OK"
else
  echo "Cluster connection: FAILED"
  exit 1
fi

echo
if [[ -z "$SELECTED_NAMESPACE" ]]; then
  if (( NON_INTERACTIVE )); then
    echo "ERROR: non-interactive mode needs -n <namespace>." >&2
    exit 1
  else
    echo
    NAMESPACES=()
    while IFS= read -r line; do
      [[ -n "$line" ]] && NAMESPACES+=("$line")
    done < <(kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    if [[ ${#NAMESPACES[@]} -eq 0 ]]; then
      echo "ERROR: no namespaces found." >&2
      exit 1
    fi
    SELECTED_NAMESPACE="$(pick_from_list 'Which namespace do you want to check?' "${NAMESPACES[@]}")"
  fi
else
  if ! is_safe_namespace_name "$SELECTED_NAMESPACE"; then
    echo "ERROR: namespace contains unsafe characters: $SELECTED_NAMESPACE" >&2
    exit 1
  fi
  if ! kubectl get ns "$SELECTED_NAMESPACE" >/dev/null 2>&1; then
    echo "ERROR: namespace not found: $SELECTED_NAMESPACE" >&2
    exit 1
  fi
fi

if ! is_safe_namespace_name "$SELECTED_NAMESPACE"; then
  echo "ERROR: namespace contains unsafe characters: $SELECTED_NAMESPACE" >&2
  exit 1
fi

echo
echo "Selected namespace: $SELECTED_NAMESPACE"

echo
echo "== Node Status =="
NODE_LINES="$(kubectl get nodes --no-headers 2>/dev/null || true)"
if [[ -z "$NODE_LINES" ]]; then
  echo "No nodes returned by kubectl."
else
  node_summary="$(printf '%s\n' "$NODE_LINES" | awk 'BEGIN { bad = 0; total = 0 } { name = $1; status = $2; roles = $3; age = $4; version = $5; printf "%s|%s|%s|%s|%s\n", name, status, roles, age, version; if (status != "Ready") bad++; total++ } END { printf "%d|%d", total, bad }')"
  node_total="${node_summary%%|*}"
  node_not_ready="${node_summary##*|}"
  {
    printf '%s\n' 'Name|Status|Roles|Age|Version'
    printf '%s\n' "$NODE_LINES" | awk '{ name = $1; status = $2; roles = $3; age = $4; version = $5; printf "%s|%s|%s|%s|%s\n", name, status, roles, age, version }'
  } | print_boxed_table "== Node Status =="
fi

echo
echo "== Restarted Pods (top 10 by restart count) =="
POD_ROWS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && POD_ROWS+=("$line")
done < <(kubectl get pods -n "$SELECTED_NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.status.containerStatuses[*].restartCount}{"|"}{.status.phase}{"|"}{.metadata.creationTimestamp}{"\n"}{end}' 2>/dev/null || true)

if [[ ${#POD_ROWS[@]} -eq 0 ]]; then
  echo "No pods found in namespace $SELECTED_NAMESPACE"
else
  {
    printf '%s\n' 'Name|Restarts|Phase|Age'
    printf '%s\n' "${POD_ROWS[@]}" | while IFS='|' read -r pod restarts phase created; do
      restarts=${restarts:-0}
      created=${created:-unknown}
      phase=${phase:-unknown}
      printf '%s|%s|%s|%s\n' "$pod" "$restarts" "$phase" "$created"
    done | sort -t'|' -k2,2nr | head -n 10
  } | print_boxed_table "== Restarted Pods (top 10 by restart count) =="
fi

echo
echo "== Top 10 CPU Consumers =="
if kubectl top pods -n "$SELECTED_NAMESPACE" --no-headers >/dev/null 2>&1; then
  {
    printf '%s\n' 'Name|CPU|Memory'
    kubectl top pods -n "$SELECTED_NAMESPACE" --no-headers | sort -k2 -hr | head -n 10 | awk 'BEGIN {} { printf "%s|%s|%s\n", $1, $2, $3 }'
  } | print_boxed_table "== Top 10 CPU Consumers =="
else
  echo "Metrics unavailable. Install metrics-server or ensure it is healthy."
fi

echo
echo "== Top 10 Memory Consumers =="
if kubectl top pods -n "$SELECTED_NAMESPACE" --no-headers >/dev/null 2>&1; then
  {
    printf '%s\n' 'Name|CPU|Memory'
    kubectl top pods -n "$SELECTED_NAMESPACE" --no-headers | sort -k3 -hr | head -n 10 | awk 'BEGIN {} { printf "%s|%s|%s\n", $1, $2, $3 }'
  } | print_boxed_table "== Top 10 Memory Consumers =="
else
  echo "Metrics unavailable. Install metrics-server or ensure it is healthy."
fi

echo
echo "== Workload Safety Scope =="
RESOURCE_GAPS=0
PROBE_GAPS=0
ROOT_RISKS=0
PRIVILEGED_RISKS=0
READONLY_ROOTFS_GAPS=0

CONTAINER_POLICY_ROWS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && CONTAINER_POLICY_ROWS+=("$line")
done < <(collect_container_policy_rows "$SELECTED_NAMESPACE")

if [[ ${#CONTAINER_POLICY_ROWS[@]} -gt 0 ]]; then
  {
    printf '%s\n' 'Pod|Container|Resources|Probes|Security'
    for line in "${CONTAINER_POLICY_ROWS[@]}"; do
      IFS='|' read -r pod_name container_name req_cpu req_mem lim_cpu lim_mem has_readiness has_liveness run_as_non_root run_as_user privileged read_only_rootfs <<< "$line"

      req_state="req:${req_cpu:-missing}/${req_mem:-missing}"
      lim_state="lim:${lim_cpu:-missing}/${lim_mem:-missing}"
      probe_state="ready:${has_readiness:-no} live:${has_liveness:-no}"
      sec_state="nonRoot:${run_as_non_root:-unset} user:${run_as_user:-unset} priv:${privileged:-unset} rofs:${read_only_rootfs:-unset}"

      printf '%s|%s|%s %s|%s|%s\n' "$pod_name" "$container_name" "$req_state" "$lim_state" "$probe_state" "$sec_state"

      if [[ -z "$req_cpu" || -z "$req_mem" || -z "$lim_cpu" || -z "$lim_mem" ]]; then
        RESOURCE_GAPS=$((RESOURCE_GAPS + 1))
      fi
      if [[ "$has_readiness" != "yes" || "$has_liveness" != "yes" ]]; then
        PROBE_GAPS=$((PROBE_GAPS + 1))
      fi
      if [[ "$run_as_non_root" != "true" ]]; then
        if [[ -z "$run_as_user" || "$run_as_user" == "0" ]]; then
          ROOT_RISKS=$((ROOT_RISKS + 1))
        fi
      fi
      if [[ "$privileged" == "true" ]]; then
        PRIVILEGED_RISKS=$((PRIVILEGED_RISKS + 1))
      fi
      if [[ "$read_only_rootfs" != "true" ]]; then
        READONLY_ROOTFS_GAPS=$((READONLY_ROOTFS_GAPS + 1))
      fi
    done
  } | print_boxed_table "== Workload Safety Scope =="
else
  echo "No container workload data found in namespace."
fi

NETWORK_POLICY_COUNT=0
if kubectl get networkpolicy -n "$SELECTED_NAMESPACE" --no-headers >/dev/null 2>&1; then
  NETWORK_POLICY_COUNT=$(kubectl get networkpolicy -n "$SELECTED_NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')
fi

PDB_COUNT=0
if kubectl get pdb -n "$SELECTED_NAMESPACE" --no-headers >/dev/null 2>&1; then
  PDB_COUNT=$(kubectl get pdb -n "$SELECTED_NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')
fi

EXPOSED_SERVICE_COUNT=0
if kubectl get svc -n "$SELECTED_NAMESPACE" --no-headers >/dev/null 2>&1; then
  EXPOSED_SERVICE_COUNT=$(kubectl get svc -n "$SELECTED_NAMESPACE" --no-headers -o custom-columns=TYPE:.spec.type 2>/dev/null | awk 'BEGIN {} $1 != "ClusterIP" && $1 != "" {count++} END {print count + 0}')
fi
{
  printf '%s\n' 'Control|State|Count'
  printf '%s|%s|%s\n' 'NetworkPolicy' "$([[ "$NETWORK_POLICY_COUNT" -gt 0 ]] && echo present || echo missing)" "$NETWORK_POLICY_COUNT"
  printf '%s|%s|%s\n' 'PodDisruptionBudget' "$([[ "$PDB_COUNT" -gt 0 ]] && echo present || echo missing)" "$PDB_COUNT"
  printf '%s|%s|%s\n' 'Non-ClusterIP Services' "$([[ "$EXPOSED_SERVICE_COUNT" -gt 0 ]] && echo exposed || echo internal)" "$EXPOSED_SERVICE_COUNT"
} | print_boxed_table "== Exposure & Resilience =="

echo
echo "== Critical Vulnerability Check =="
CRIT_VULNS=0
if ! command -v trivy >/dev/null 2>&1; then
  if (( INSTALL_TRIVY_AUTO )); then
    if install_trivy && command -v trivy >/dev/null 2>&1; then
      echo "Trivy installation complete. Proceeding with vulnerability scan."
    else
      echo "Trivy installation failed. Skipping image vulnerability scan."
    fi
  elif (( NON_INTERACTIVE )); then
    echo "trivy not installed. Skipping image vulnerability scan in non-interactive mode."
  elif prompt_yes_no "Trivy is not installed. Do you want to install it now?"; then
    if install_trivy && command -v trivy >/dev/null 2>&1; then
      echo "Trivy installation complete. Proceeding with vulnerability scan."
    else
      echo "Trivy installation failed. Skipping image vulnerability scan."
    fi
  else
    echo "Trivy installation skipped. Skipping image vulnerability scan."
  fi
fi

if command -v trivy >/dev/null 2>&1; then
  IMAGE_LIST="$(kubectl get pods -n "$SELECTED_NAMESPACE" -o jsonpath='{range .items[*].spec.containers[*]}{.image}{"\n"}{end}' | sort -u)"
  if [[ -n "$IMAGE_LIST" ]]; then
    while IFS= read -r image; do
      [[ -z "$image" ]] && continue
      # SECURITY_NOTE: Properly quote and escape image name to prevent command injection
      if [[ ! "$image" =~ ^[a-zA-Z0-9./:@_-]+$ ]]; then
        echo "WARNING: skipping image with suspicious characters: $image" >&2
        continue
      fi
      echo "Scanning: ${image}"
      # Use array and quoted expansion to safely pass image name
      TRIVY_OUTPUT="$(trivy image --quiet --severity CRITICAL --ignore-unfixed -- "${image}" 2>/dev/null || true)"
      if printf '%s' "$TRIVY_OUTPUT" | grep -Eq 'CRITICAL'; then
        echo "  CRITICAL findings present"
        CRIT_VULNS=$((CRIT_VULNS + 1))
      else
        echo "  No critical findings reported"
      fi
    done <<< "$IMAGE_LIST"
  else
    echo "No container images found in namespace."
  fi
fi

echo
echo "== ${APP_NAME} Report =="
echo "Selected cluster:   $SELECTED_CONTEXT"
echo "Selected namespace: $SELECTED_NAMESPACE"

TOTAL_NODES=0
NOT_READY_NODES=0
if [[ -n "$NODE_LINES" ]]; then
  TOTAL_NODES=$(printf '%s\n' "$NODE_LINES" | wc -l | tr -d ' ')
  NOT_READY_NODES=$(printf '%s\n' "$NODE_LINES" | awk '$2 != "Ready" {count++} END {print count + 0}')
fi

PODS_JSON="$(kubectl get pods -n "$SELECTED_NAMESPACE" -o json 2>/dev/null || true)"
TOTAL_RESTARTS=0
PENDING_PODS=0
if [[ -n "$PODS_JSON" ]]; then
  POD_SCORE_ROWS=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && POD_SCORE_ROWS+=("$line")
  done < <(
    kubectl get pods -n "$SELECTED_NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.status.phase}{"|"}{.metadata.creationTimestamp}{"|"}{range .status.containerStatuses[*]}{.restartCount}{" "}{end}{"\n"}{end}' 2>/dev/null || true
  )

  if [[ ${#POD_SCORE_ROWS[@]} -gt 0 ]]; then
    while IFS='|' read -r _pod phase _created restarts; do
      phase="$(trim "${phase:-}")"
      restarts="$(trim "${restarts:-0}")"
      [[ "$phase" == "Pending" ]] && PENDING_PODS=$((PENDING_PODS + 1))
      if [[ -n "$restarts" ]]; then
        for restart_value in $restarts; do
          [[ "$restart_value" =~ ^[0-9]+$ ]] || continue
          TOTAL_RESTARTS=$((TOTAL_RESTARTS + restart_value))
        done
      fi
    done < <(printf '%s\n' "${POD_SCORE_ROWS[@]}")
  fi
fi

MEM_USAGE_PCT=0
CPU_USAGE_PCT=0
if kubectl top nodes >/dev/null 2>&1; then
  NODE_USAGE=$(kubectl top nodes --no-headers | awk 'BEGIN {} { cpu += parse_cpu($2); mem += parse_mem($4) } function parse_cpu(v) { sub(/m$/, "", v); return v + 0 } function parse_mem(v) { if (v ~ /Gi$/) { sub(/Gi$/, "", v); return (v + 0) * 1024 } if (v ~ /Mi$/) { sub(/Mi$/, "", v); return v + 0 } if (v ~ /Ki$/) { sub(/Ki$/, "", v); return (v + 0) / 1024 } return v + 0 } END { printf "%f|%f", cpu + 0, mem + 0 }')
  CPU_USED=$(printf '%s' "$NODE_USAGE" | cut -d'|' -f1)
  MEM_USED_MIB=$(printf '%s' "$NODE_USAGE" | cut -d'|' -f2)
  MEM_TOTAL_MIB=$(kubectl get nodes -o jsonpath='{range .items[*]}{.status.allocatable.memory}{"\n"}{end}' | awk '{ if ($1 ~ /Ki$/) { sub(/Ki$/, "", $1); sum += ($1 + 0) / 1024 } else if ($1 ~ /Mi$/) { sub(/Mi$/, "", $1); sum += $1 + 0 } else if ($1 ~ /Gi$/) { sub(/Gi$/, "", $1); sum += ($1 + 0) * 1024 } else sum += $1 + 0 } END { print sum + 0 }')
  CPU_TOTAL_MCPU=$(kubectl get nodes -o jsonpath='{range .items[*]}{.status.allocatable.cpu}{"\n"}{end}' | awk '{ if ($1 ~ /m$/) { sub(/m$/, "", $1); sum += $1 + 0 } else sum += ($1 + 0) * 1000 } END { print sum + 0 }')
  CPU_USAGE_PCT=$(as_percent "$CPU_USED" "$CPU_TOTAL_MCPU")
  MEM_USAGE_PCT=$(as_percent "$MEM_USED_MIB" "$MEM_TOTAL_MIB")
fi

SCORE=100
SCORE_PENALTY_TOTAL=0
SCORE_BREAKDOWN_ROWS=()
RECOMMENDATION_ROWS=()
SERVICE_ACCOUNT_DEFAULT_USES=0
RBAC_ROLE_COUNT=0
RBAC_ROLEBINDING_COUNT=0
RBAC_CLUSTERROLEBINDING_SA_COUNT=0
RBAC_SA_CLUSTER_SCOPE_COUNT=0
RBAC_SA_HIGH_RISK_COUNT=0
RBAC_SA_SECRET_ACCESS_COUNT=0
AFFINITY_GAPS=0
AFFINITY_REQUIRED_GAPS=0

SERVICE_ACCOUNT_ROWS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && SERVICE_ACCOUNT_ROWS+=("$line")
done < <(collect_service_account_rows "$SELECTED_NAMESPACE")

if [[ ${#SERVICE_ACCOUNT_ROWS[@]} -gt 0 ]]; then
  for line in "${SERVICE_ACCOUNT_ROWS[@]}"; do
    IFS='|' read -r pod_name service_account automount default_sa <<< "$line"
    if [[ "$default_sa" == "yes" ]]; then
      SERVICE_ACCOUNT_DEFAULT_USES=$((SERVICE_ACCOUNT_DEFAULT_USES + 1))
    fi
  done

  {
    printf '%s\n' 'Pod|ServiceAccount|Automount Token|Default SA'
    for line in "${SERVICE_ACCOUNT_ROWS[@]}"; do
      IFS='|' read -r pod_name service_account automount default_sa <<< "$line"
      printf '%s|%s|%s|%s\n' "$pod_name" "$service_account" "$automount" "$default_sa"
    done
  } | print_boxed_table "== Service Accounts =="
else
  echo "No service account data found in namespace."
fi

RBAC_ROWS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && RBAC_ROWS+=("$line")
done < <(collect_rbac_rows "$SELECTED_NAMESPACE")

if [[ ${#RBAC_ROWS[@]} -gt 0 ]]; then
  for line in "${RBAC_ROWS[@]}"; do
    IFS='|' read -r item_type item_name item_kind item_count <<< "$line"
    case "$item_type" in
      role) RBAC_ROLE_COUNT=$((RBAC_ROLE_COUNT + 1)) ;;
      rolebinding) RBAC_ROLEBINDING_COUNT=$((RBAC_ROLEBINDING_COUNT + 1)) ;;
      clusterrolebinding) RBAC_CLUSTERROLEBINDING_SA_COUNT=$((RBAC_CLUSTERROLEBINDING_SA_COUNT + item_count)) ;;
    esac
  done

  {
    printf '%s\n' 'Type|Name|Rules/Kind|Count'
    for line in "${RBAC_ROWS[@]}"; do
      IFS='|' read -r item_type item_name item_kind item_count <<< "$line"
      printf '%s|%s|%s|%s\n' "$item_type" "$item_name" "$item_kind" "$item_count"
    done
  } | print_boxed_table "== RBAC Coverage =="
else
  echo "No RBAC data found in namespace."
fi

RBAC_REVIEW_ROWS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && RBAC_REVIEW_ROWS+=("$line")
done < <(collect_service_account_rbac_rows "$SELECTED_NAMESPACE")

if [[ ${#RBAC_REVIEW_ROWS[@]} -gt 0 ]]; then
  for line in "${RBAC_REVIEW_ROWS[@]}"; do
    IFS='|' read -r sa_name pod_count namespace_bindings cluster_bindings risk findings <<< "$line"

    if (( cluster_bindings > 0 )); then
      RBAC_SA_CLUSTER_SCOPE_COUNT=$((RBAC_SA_CLUSTER_SCOPE_COUNT + 1))
    fi
    if [[ "$risk" == "high" ]]; then
      RBAC_SA_HIGH_RISK_COUNT=$((RBAC_SA_HIGH_RISK_COUNT + 1))
    fi
    if [[ "$findings" == *"secrets-access"* ]]; then
      RBAC_SA_SECRET_ACCESS_COUNT=$((RBAC_SA_SECRET_ACCESS_COUNT + 1))
    fi
  done

  {
    printf '%s\n' 'ServiceAccount|Pods|RoleBindings|ClusterBindings|Risk|Findings'
    for line in "${RBAC_REVIEW_ROWS[@]}"; do
      IFS='|' read -r sa_name pod_count namespace_bindings cluster_bindings risk findings <<< "$line"
      printf '%s|%s|%s|%s|%s|%s\n' "$sa_name" "$pod_count" "$namespace_bindings" "$cluster_bindings" "$risk" "$findings"
    done
  } | print_boxed_table "== Service Account RBAC Review =="
else
  echo "No scoped service account RBAC review data found in namespace."
fi

AFFINITY_ROWS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && AFFINITY_ROWS+=("$line")
done < <(collect_affinity_rows "$SELECTED_NAMESPACE")

if [[ ${#AFFINITY_ROWS[@]} -gt 0 ]]; then
  for line in "${AFFINITY_ROWS[@]}"; do
    IFS='|' read -r pod_name has_node_aff has_pod_aff has_pod_anti required_node required_pod required_anti <<< "$line"

    if [[ "$has_node_aff" != "yes" || "$has_pod_aff" != "yes" || "$has_pod_anti" != "yes" ]]; then
      AFFINITY_GAPS=$((AFFINITY_GAPS + 1))
    fi
    if [[ "$required_node" != "yes" || "$required_pod" != "yes" || "$required_anti" != "yes" ]]; then
      AFFINITY_REQUIRED_GAPS=$((AFFINITY_REQUIRED_GAPS + 1))
    fi
  done

  {
    printf '%s\n' 'Pod|Node Affinity|Pod Affinity|Pod Anti-Affinity|Required Node|Required Pod|Required Anti'
    for line in "${AFFINITY_ROWS[@]}"; do
      IFS='|' read -r pod_name has_node_aff has_pod_aff has_pod_anti required_node required_pod required_anti <<< "$line"
      printf '%s|%s|%s|%s|%s|%s|%s\n' "$pod_name" "$has_node_aff" "$has_pod_aff" "$has_pod_anti" "$required_node" "$required_pod" "$required_anti"
    done
  } | print_boxed_table "== Scheduling Affinity =="
else
  echo "No pod affinity data found in namespace."
fi

if (( TOTAL_NODES > 0 )); then
  NODE_PENALTY=$((NOT_READY_NODES * 20))
  add_score_deduction "Node readiness" "$NODE_PENALTY" "${NOT_READY_NODES} node(s) not Ready"
  SCORE=$((SCORE - NODE_PENALTY))
fi

if (( PENDING_PODS > 0 )); then
  PENDING_PENALTY=$((PENDING_PODS * 10))
  add_score_deduction "Pending pods" "$PENDING_PENALTY" "${PENDING_PODS} pod(s) pending"
  SCORE=$((SCORE - PENDING_PENALTY))
fi

if (( TOTAL_RESTARTS > 0 )); then
  RESTART_PENALTY=$((TOTAL_RESTARTS * 2))
  if (( RESTART_PENALTY > 20 )); then
    RESTART_PENALTY=20
  fi
  add_score_deduction "Pod restarts" "$RESTART_PENALTY" "${TOTAL_RESTARTS} restart(s), capped at 20"
  SCORE=$((SCORE - RESTART_PENALTY))
fi

if (( RESOURCE_GAPS > 0 )); then
  RESOURCE_PENALTY=$((RESOURCE_GAPS * 4))
  if (( RESOURCE_PENALTY > 20 )); then
    RESOURCE_PENALTY=20
  fi
  add_score_deduction "Resource requests/limits" "$RESOURCE_PENALTY" "${RESOURCE_GAPS} container(s) missing resource settings"
  SCORE=$((SCORE - RESOURCE_PENALTY))
fi

if (( PROBE_GAPS > 0 )); then
  PROBE_PENALTY=$((PROBE_GAPS * 5))
  if (( PROBE_PENALTY > 20 )); then
    PROBE_PENALTY=20
  fi
  add_score_deduction "Probes" "$PROBE_PENALTY" "${PROBE_GAPS} container(s) missing readiness/liveness probes"
  SCORE=$((SCORE - PROBE_PENALTY))
fi

if (( ROOT_RISKS > 0 )); then
  ROOT_PENALTY=$((ROOT_RISKS * 8))
  if (( ROOT_PENALTY > 24 )); then
    ROOT_PENALTY=24
  fi
  add_score_deduction "Run-as-non-root" "$ROOT_PENALTY" "${ROOT_RISKS} container(s) appear to run as root"
  SCORE=$((SCORE - ROOT_PENALTY))
fi

if (( PRIVILEGED_RISKS > 0 )); then
  PRIVILEGED_PENALTY=$((PRIVILEGED_RISKS * 10))
  if (( PRIVILEGED_PENALTY > 20 )); then
    PRIVILEGED_PENALTY=20
  fi
  add_score_deduction "Privileged containers" "$PRIVILEGED_PENALTY" "${PRIVILEGED_RISKS} container(s) marked privileged"
  SCORE=$((SCORE - PRIVILEGED_PENALTY))
fi

if (( READONLY_ROOTFS_GAPS > 0 )); then
  READONLY_ROOTFS_PENALTY=$((READONLY_ROOTFS_GAPS * 2))
  if (( READONLY_ROOTFS_PENALTY > 12 )); then
    READONLY_ROOTFS_PENALTY=12
  fi
  add_score_deduction "Read-only rootfs" "$READONLY_ROOTFS_PENALTY" "${READONLY_ROOTFS_GAPS} container(s) without read-only root filesystem"
  SCORE=$((SCORE - READONLY_ROOTFS_PENALTY))
fi

if (( NETWORK_POLICY_COUNT == 0 )); then
  add_score_deduction "NetworkPolicy" 10 "no NetworkPolicy objects found"
  SCORE=$((SCORE - 10))
fi

if (( PDB_COUNT == 0 )); then
  add_score_deduction "PodDisruptionBudget" 8 "no PodDisruptionBudget objects found"
  SCORE=$((SCORE - 8))
fi

if (( EXPOSED_SERVICE_COUNT > 0 )); then
  SERVICE_PENALTY=$((EXPOSED_SERVICE_COUNT * 4))
  if (( SERVICE_PENALTY > 12 )); then
    SERVICE_PENALTY=12
  fi
  add_score_deduction "Service exposure" "$SERVICE_PENALTY" "${EXPOSED_SERVICE_COUNT} service(s) expose a non-ClusterIP type"
  SCORE=$((SCORE - SERVICE_PENALTY))
  add_recommendation "Review exposed services" "Move external access behind an Ingress or load balancer only where needed, and keep internal services on ClusterIP."
fi

if (( AFFINITY_GAPS > 0 )); then
  AFFINITY_PENALTY=$((AFFINITY_GAPS * 3))
  if (( AFFINITY_PENALTY > 15 )); then
    AFFINITY_PENALTY=15
  fi
  add_score_deduction "Affinity rules" "$AFFINITY_PENALTY" "${AFFINITY_GAPS} pod(s) do not define node/pod affinity or anti-affinity"
  SCORE=$((SCORE - AFFINITY_PENALTY))
  add_recommendation "Add scheduling affinity rules" "Use node affinity for placement and pod anti-affinity for spreading replicas across nodes or zones."
fi

if (( SERVICE_ACCOUNT_DEFAULT_USES > 0 )); then
  SA_PENALTY=$((SERVICE_ACCOUNT_DEFAULT_USES * 5))
  if (( SA_PENALTY > 15 )); then
    SA_PENALTY=15
  fi
  add_score_deduction "Default service account" "$SA_PENALTY" "${SERVICE_ACCOUNT_DEFAULT_USES} pod(s) use the default service account"
  SCORE=$((SCORE - SA_PENALTY))
  add_recommendation "Use dedicated service accounts" "Assign each workload a namespace-specific service account instead of the default account."
fi

if (( RBAC_ROLEBINDING_COUNT == 0 )); then
  add_score_deduction "RBAC bindings" 8 "no RoleBinding objects found in the namespace"
  SCORE=$((SCORE - 8))
  add_recommendation "Add namespace RoleBindings" "Bind only the permissions the workload needs instead of relying on implicit access."
fi

if (( RBAC_SA_CLUSTER_SCOPE_COUNT > 0 )); then
  CRB_PENALTY=$((RBAC_SA_CLUSTER_SCOPE_COUNT * 4))
  if (( CRB_PENALTY > 12 )); then
    CRB_PENALTY=12
  fi
  add_score_deduction "Cluster-scope service account bindings" "$CRB_PENALTY" "${RBAC_SA_CLUSTER_SCOPE_COUNT} used service account(s) have ClusterRoleBinding access"
  SCORE=$((SCORE - CRB_PENALTY))
  add_recommendation "Review ClusterRoleBindings" "Prefer namespace-scoped roles unless the workload truly needs cluster-wide access."
fi

if (( RBAC_SA_HIGH_RISK_COUNT > 0 )); then
  RBAC_RISK_PENALTY=$((RBAC_SA_HIGH_RISK_COUNT * 6))
  if (( RBAC_RISK_PENALTY > 18 )); then
    RBAC_RISK_PENALTY=18
  fi
  add_score_deduction "High-risk RBAC rules" "$RBAC_RISK_PENALTY" "${RBAC_SA_HIGH_RISK_COUNT} used service account(s) have cluster-admin or wildcard permissions"
  SCORE=$((SCORE - RBAC_RISK_PENALTY))
  add_recommendation "Reduce wildcard RBAC access" "Replace cluster-admin and wildcard verbs/resources with narrowly scoped rules for each workload."
fi

if (( RBAC_SA_SECRET_ACCESS_COUNT > 0 )); then
  RBAC_SECRET_PENALTY=$((RBAC_SA_SECRET_ACCESS_COUNT * 3))
  if (( RBAC_SECRET_PENALTY > 9 )); then
    RBAC_SECRET_PENALTY=9
  fi
  add_score_deduction "Secret-access RBAC" "$RBAC_SECRET_PENALTY" "${RBAC_SA_SECRET_ACCESS_COUNT} used service account(s) can read or modify secrets"
  SCORE=$((SCORE - RBAC_SECRET_PENALTY))
  add_recommendation "Limit secret access" "Grant secret permissions only to workloads that must read or manage secrets."
fi

if (( CPU_USAGE_PCT >= 80 )); then
  add_score_deduction "CPU pressure" 15 "CPU usage at ${CPU_USAGE_PCT}%"
  SCORE=$((SCORE - 15))
elif (( CPU_USAGE_PCT >= 60 )); then
  add_score_deduction "CPU pressure" 7 "CPU usage at ${CPU_USAGE_PCT}%"
  SCORE=$((SCORE - 7))
fi

if (( MEM_USAGE_PCT >= 80 )); then
  add_score_deduction "Memory pressure" 20 "Memory usage at ${MEM_USAGE_PCT}%"
  SCORE=$((SCORE - 20))
elif (( MEM_USAGE_PCT >= 60 )); then
  add_score_deduction "Memory pressure" 10 "Memory usage at ${MEM_USAGE_PCT}%"
  SCORE=$((SCORE - 10))
fi

if [[ "$CRIT_VULNS" -gt 0 ]]; then
  VULN_PENALTY=$((CRIT_VULNS * 25))
  add_score_deduction "Critical vulnerabilities" "$VULN_PENALTY" "${CRIT_VULNS} image(s) with critical findings"
  SCORE=$((SCORE - (CRIT_VULNS * 25)))
fi

if (( SCORE < 0 )); then
  SCORE=0
fi

echo "- Node readiness penalty: ${NOT_READY_NODES}"
echo "- Pending pods penalty signal: ${PENDING_PODS}"
echo "- Total restart count: ${TOTAL_RESTARTS}"
echo "- Resource gaps: ${RESOURCE_GAPS}"
echo "- Probe gaps: ${PROBE_GAPS}"
echo "- Root-user risks: ${ROOT_RISKS}"
echo "- Privileged container risks: ${PRIVILEGED_RISKS}"
echo "- Writable rootfs gaps: ${READONLY_ROOTFS_GAPS}"
echo "- NetworkPolicy count: ${NETWORK_POLICY_COUNT}"
echo "- PodDisruptionBudget count: ${PDB_COUNT}"
echo "- Exposed service count: ${EXPOSED_SERVICE_COUNT}"
echo "- CPU usage: ${CPU_USAGE_PCT}%"
echo "- Memory usage: ${MEM_USAGE_PCT}%"
echo "- Critical vulnerability signals: ${CRIT_VULNS}"
if [[ ${#SCORE_BREAKDOWN_ROWS[@]} -gt 0 ]]; then
  {
    printf '%s\n' 'Factor|Impact|Detail'
    printf '%s\n' "${SCORE_BREAKDOWN_ROWS[@]}"
    printf '%s|%s|%s\n' 'Base score' 100 'starting point'
    printf '%s|%s|%s\n' 'Total deductions' "-${SCORE_PENALTY_TOTAL}" "sum of applied penalties"
    printf '%s|%s|%s\n' 'Final score' "$SCORE" "100 - ${SCORE_PENALTY_TOTAL} = ${SCORE}"
  } | print_boxed_table "== ${APP_NAME} Score Breakdown =="
fi

if [[ ${#RECOMMENDATION_ROWS[@]} -gt 0 ]]; then
  {
    printf '%s\n' 'Action|Why it helps'
    printf '%s\n' "${RECOMMENDATION_ROWS[@]}"
  } | print_boxed_table "== Improvement Suggestions =="
else
  {
    printf '%s\n' 'Action|Why it helps'
    printf '%s|%s\n' 'No immediate fixes flagged' 'Current namespace configuration looks healthy for the checks we ran.'
  } | print_boxed_table "== Improvement Suggestions =="
fi
if (( SCORE >= 95 )); then
  GRADE="A+"
  GRADE_LABEL="Production hardened"
elif (( SCORE >= 85 )); then
  GRADE="A"
  GRADE_LABEL="Production ready"
elif (( SCORE >= 70 )); then
  GRADE="B"
  GRADE_LABEL="Mostly healthy, minor gaps"
elif (( SCORE >= 55 )); then
  GRADE="C"
  GRADE_LABEL="Needs attention"
elif (( SCORE >= 40 )); then
  GRADE="D"
  GRADE_LABEL="Significant issues"
else
  GRADE="F"
  GRADE_LABEL="Critical — not production ready"
fi

echo "Final score: ${SCORE}/100 = 100 - ${SCORE_PENALTY_TOTAL}"
printf 'Grade: %s — %s\n' "$GRADE" "$GRADE_LABEL"
print_grade_dashboard "$SELECTED_CONTEXT" "$SELECTED_NAMESPACE" "$SCORE" "$SCORE_PENALTY_TOTAL" "$GRADE" "$GRADE_LABEL" "$TOTAL_NODES" "$NOT_READY_NODES" "$PENDING_PODS" "$TOTAL_RESTARTS" "$CPU_USAGE_PCT" "$MEM_USAGE_PCT" "$CRIT_VULNS"

if [[ -n "$EXPORT_CSV_FILE" ]]; then
  export_report_csv "$EXPORT_CSV_FILE"
  echo "CSV export written: $EXPORT_CSV_FILE"
fi

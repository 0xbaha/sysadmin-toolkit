#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT
#
# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : django_dep_audit.sh
# PURPOSE       : Audit a Django project's Python dependencies for known vulnerabilities.
#                 Designed for local use and CI. Fails with non-zero exit when issues found.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-09-21
# LAST UPDATED  : 2025-09-21
# VERSION       : 1.0.0
# =========================================================================================
#
# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script inspects a (Django) Python repository and audits dependencies against
# public advisories using two scanners:
#   - pip-audit (PyPI Advisory DB)
#   - Safety (pyup DB)
#
# Features:
# - Detects dependency source: requirements*.txt, Poetry (pyproject.toml), Pipenv (Pipfile.lock)
# - Resolves to a pinned requirements file for consistent scanning
# - Runs pip-audit and/or Safety (can skip either)
# - Supports severity threshold (low|medium|high|critical) for failure decision
# - Produces JSON artifacts and a brief human summary in an output directory
# - Isolates execution in a temporary virtualenv; cleans up on exit
# - CI friendly (non-zero exit if vulnerabilities at/above threshold)
#
# Workflow:
# 1) Locate project directory (default: current dir) and detect Django (heuristic).
# 2) Export/assemble a fully-pinned requirements file.
# 3) Create ephemeral venv and install audit tools.
# 4) Execute scanners, collect JSON outputs, generate summary.
# 5) Exit 1 if findings meet/exceed severity threshold; else 0.
# =========================================================================================
#
# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - Modularity: separate resolve / audit / summarize steps
# - Robustness: strict mode, traps, structured logs, explicit exit codes
# - Readability: clear function names and comments
# - Least Surprise: artifacts saved under ./output by default
# =========================================================================================
#
# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Backend devs, CI engineers, AppSec/DevSecOps, SREs maintaining Python/Django services
# =========================================================================================
#
# =========================================================================================
# USAGE
# =========================================================================================
# Permissions:
#   chmod +x ./django_dep_audit.sh
#
# Syntax:
#   ./django_dep_audit.sh [options]
#
# Options:
#   -h                 Show help
#   -v                 Verbose logs
#   -d                 Debug (set -x)
#   -p <path>          Project path (default: current directory)
#   -o <dir>           Output directory for artifacts (default: ./output)
#   -s <severity>      Fail threshold: low|medium|high|critical (default: low)
#   -A                 Skip pip-audit
#   -S                 Skip Safety
#   -n                 Dry run (show what would be done; no scanning)
#   --no-color         Disable colored output
#
# Examples:
#   ./django_dep_audit.sh
#   ./django_dep_audit.sh -p /repo/service -s high
#   ./django_dep_audit.sh -S            # run only pip-audit
#   ./django_dep_audit.sh -A -s critical# run only Safety; fail on critical
# =========================================================================================
#
# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# Place in repo (e.g., ./scripts/) or in PATH; make executable.
# Dependencies: bash, python3 (with venv module), coreutils, grep, awk, sed.
# =========================================================================================
#
# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# Required interpreter: /bin/bash
# Required tools: python3, grep, awk, sed, coreutils
# Python tools installed in ephemeral venv: pip-audit, safety, poetry/pipenv (if needed)
# =========================================================================================
#
# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# Logs to stdout/stderr with levels; optional log file in ./logs (timestamped).
# Format: [YYYY-MM-DD HH:MM:SS TZ] [LEVEL] [SCRIPT] - Message
# =========================================================================================
#
# =========================================================================================
# OUTPUTS
# =========================================================================================
# - <output_dir>/pip_audit_<timestamp>.json
# - <output_dir>/safety_<timestamp>.json
# - <output_dir>/summary_<timestamp>.txt
# Exit codes:
#   0: No vulnerabilities meeting threshold
#   1: Vulnerabilities found >= threshold
#   2: Dependency/tooling error
#   3: Configuration/arguments error
#   6: File system error
# =========================================================================================
#
# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - Uses network to query advisories (pip-audit, Safety). Run behind proxy if needed.
# - Does not install project dependencies; only audit tools into an ephemeral venv.
# - Do not pass untrusted paths without review; all variables are quoted.
# =========================================================================================

# -----------------------------------------------------------------------------------------
# Strict mode & runtime basics (adapted from your template)
# -----------------------------------------------------------------------------------------
set -euo pipefail
# set -x   # enable via -d

# ---------------------------------- Metadata ---------------------------------------------
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ---------------------------------- Defaults ---------------------------------------------
VERBOSE=false
DEBUG_MODE=false
DRY_RUN=false
NO_COLOR=false
AUTO_INSTALL=false         # NEW: allow best‑effort apt install of python3-venv/virtualenv
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true

DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}/output"
DEFAULT_LOG_DIR="${SCRIPT_DIR}/logs"
DEFAULT_LOG_FILE="${DEFAULT_LOG_DIR}/${SCRIPT_NAME%.sh}_${SCRIPT_RUN_TIMESTAMP}.log"

PROJECT_DIR="$PWD"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
LOG_FILE="${DEFAULT_LOG_FILE}"
LOG_TO_FILE=true
LOG_LEVEL="INFO"           # DEBUG|INFO|WARN|ERROR|CRITICAL

FAIL_ON_SEVERITY="low"     # low|medium|high|critical
SKIP_PIP_AUDIT=false
SKIP_SAFETY=false

# Will be set after OUTPUT_DIR is finalized
TEMP_DIR=""
VENV_DIR=""
REQS_TXT=""
PIP_AUDIT_JSON=""
SAFETY_JSON=""
SUMMARY_TXT=""

# ---------------------------------- Colors -----------------------------------------------
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
  COLOR_RESET=$'\033[0m'
  COLOR_RED=$'\033[0;31m'
  COLOR_GREEN=$'\033[0;32m'
  COLOR_YELLOW=$'\033[0;33m'
  COLOR_CYAN=$'\033[0;36m'
  COLOR_BOLD=$'\033[1m'
else
  COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_CYAN=""; COLOR_BOLD=""
fi

# ---------------------------------- Logging ----------------------------------------------
log_message() {
  local level="$1"; shift
  local message="$*"
  local ts
  ts=$(date +"%Y-%m-%d %H:%M:%S %Z")
  local lvl_up=${level^^}
  local prefix="[${ts}] [${lvl_up}] [${SCRIPT_NAME}]"

  local color=""
  case "${lvl_up}" in
    DEBUG) color="${COLOR_CYAN}" ;;
    INFO) color="${COLOR_GREEN}" ;;
    WARN) color="${COLOR_YELLOW}" ;;
    ERROR) color="${COLOR_RED}" ;;
    CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
  esac

  declare -A level_map=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
  local cur=${level_map[${LOG_LEVEL^^}]:-1}
  local msg=${level_map[${lvl_up}]:-0}

  if [[ ${msg} -ge ${cur} ]]; then
    # stderr for WARN/ERROR/CRITICAL, stdout otherwise (DEBUG gated by VERBOSE)
    if [[ "${lvl_up}" =~ ^(WARN|ERROR|CRITICAL)$ ]]; then
      echo -e "${color}${prefix} - ${message}${COLOR_RESET}" >&2
    else
      if [[ "${lvl_up}" != "DEBUG" || "${VERBOSE}" == true ]]; then
        echo -e "${color}${prefix} - ${message}${COLOR_RESET}"
      fi
    fi
    if [[ "${LOG_TO_FILE}" == true ]]; then
      mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
      if [[ -w "$(dirname "${LOG_FILE}")" || ! -e "$(dirname "${LOG_FILE}")" ]]; then
        echo "${prefix} - ${message}" >> "${LOG_FILE}" 2>/dev/null || true
      fi
    fi
  fi

  if [[ "${lvl_up}" == "CRITICAL" ]]; then
    log_message "INFO" "Critical error encountered. Exiting script."
    exit 2
  fi
}

# ---------------------------------- Cleanup & trap ---------------------------------------
cleanup() {
  local status=$?
  log_message "INFO" "Performing cleanup..."
  if [[ -n "${VENV_DIR:-}" && -d "${VENV_DIR}" ]]; then
    rm -rf "${VENV_DIR}" || true
  fi
  if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
    rm -rf "${TEMP_DIR}" || true
  fi
  log_message "INFO" "Cleanup finished with exit status: ${status}"
}
trap cleanup EXIT INT TERM HUP

# ---------------------------------- Helpers ----------------------------------------------
usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [options]

Options:
  -h                   Show help and exit
  -v                   Verbose logging
  -d                   Debug (set -x)
  -n                   Dry run (simulate; no scanners)
  --no-color           Disable colored output
  --auto-install       Best-effort OS package install for 'python3-venv' or 'virtualenv'
  -p <path>            Project path (default: current directory)
  -o <dir>             Output directory for artifacts (default: ./output)
  -s <severity>        Fail threshold: low|medium|high|critical (default: low)
  -A                   Skip pip-audit
  -S                   Skip Safety

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} -p /repo/service -s high
  ${SCRIPT_NAME} -S                     # only pip-audit
  ${SCRIPT_NAME} -A -s critical         # only Safety; fail on critical
EOF
}

need_cmd() { command -v "$1" &>/dev/null; }     # returns 0 if found
ensure_cmd() { need_cmd "$1" || log_message "CRITICAL" "Required command '$1' not found."; }

check_dependency() {
  local cmd="$1"
  local pkg="${2:-$1}"
  if ! command -v "$cmd" &>/dev/null; then
    log_message "CRITICAL" "Required command '${cmd}' not found. Install '${pkg}'."
  fi
}

sev_rank() {
  case "${1,,}" in
    low) echo 1 ;;
    medium) echo 2 ;;
    high) echo 3 ;;
    critical) echo 4 ;;
    *) echo 1 ;;
  esac
}

# ---------------------------------- Arg parsing ------------------------------------------
parse_params() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h) usage; exit 0 ;;
      -v) VERBOSE=true; shift ;;
      -d) DEBUG_MODE=true; set -x; shift ;;
      -n) DRY_RUN=true; shift ;;
      --no-color) NO_COLOR=true; shift ;;
      --auto-install) AUTO_INSTALL=true; shift ;;
      -p) PROJECT_DIR="$2"; shift 2 ;;
      -o) OUTPUT_DIR="$2"; shift 2 ;;
      -s) FAIL_ON_SEVERITY="${2,,}"; shift 2 ;;
      -A) SKIP_PIP_AUDIT=true; shift ;;
      -S) SKIP_SAFETY=true; shift ;;
      --) shift; break ;;
      -*)
        log_message "ERROR" "Unknown option: $1"
        usage; exit 3 ;;
      *)
        log_message "ERROR" "Unexpected argument: $1"
        usage; exit 3 ;;
    esac
  done
}

# ---------------------------------- Validation & setup -----------------------------------
init_artifacts() {
  mkdir -p "${OUTPUT_DIR}" || { log_message "CRITICAL" "Cannot create output dir: ${OUTPUT_DIR}"; }
  REQS_TXT="${OUTPUT_DIR}/resolved_requirements_${SCRIPT_RUN_TIMESTAMP}.txt"
  PIP_AUDIT_JSON="${OUTPUT_DIR}/pip_audit_${SCRIPT_RUN_TIMESTAMP}.json"
  SAFETY_JSON="${OUTPUT_DIR}/safety_${SCRIPT_RUN_TIMESTAMP}.json"
  SUMMARY_TXT="${OUTPUT_DIR}/summary_${SCRIPT_RUN_TIMESTAMP}.txt"
}

validate_inputs() {
  if [[ ! -d "${PROJECT_DIR}" ]]; then
    log_message "CRITICAL" "Project directory not found: ${PROJECT_DIR}"
  fi
  mkdir -p "$(dirname "${LOG_FILE}")" || true

  case "${FAIL_ON_SEVERITY}" in
    low|medium|high|critical) : ;;
    *) log_message "CRITICAL" "Invalid severity: ${FAIL_ON_SEVERITY}. Use low|medium|high|critical." ;;
  esac

  check_dependency "python3" "python3"
  check_dependency "grep" "grep"
  check_dependency "awk" "awk"
  check_dependency "sed" "sed"
}

prepare_environment() {
  TEMP_DIR="$(mktemp -d "/tmp/${SCRIPT_NAME}.XXXXXX")"
  VENV_DIR="${TEMP_DIR}/venv"
  log_message INFO "Creating isolated virtualenv in ${VENV_DIR}"

  # 1) Prefer stdlib venv
  if python3 -m venv "${VENV_DIR}" >/dev/null 2>&1; then
    :
  else
    # 2) Try OS install (Debian/Ubuntu) if requested
    if [[ "${AUTO_INSTALL}" == true && "${DRY_RUN}" == false ]] && need_cmd apt-get; then
      log_message WARN "python3-venv not available; attempting apt-get install…"
      sudo apt-get update -y || log_message WARN "apt-get update failed (continuing)"
      sudo apt-get install -y python3-venv || log_message WARN "apt-get install python3-venv failed"
    fi
    if python3 -m venv "${VENV_DIR}" >/dev/null 2>&1; then
      :
    else
      # 3) Fallback: virtualenv
      if ! need_cmd virtualenv; then
        if [[ "${AUTO_INSTALL}" == true && "${DRY_RUN}" == false ]]; then
          log_message WARN "Installing 'virtualenv' as fallback…"
          python3 -m pip install --user virtualenv >/dev/null 2>&1 || true
        fi
      fi
      need_cmd virtualenv || log_message CRITICAL "Could not create a virtual environment. Install 'python3-venv' or 'virtualenv'."
      virtualenv -p python3 "${VENV_DIR}"
    fi
  fi

  # shellcheck disable=SC1090
  source "${VENV_DIR}/bin/activate"
  python -m pip install --upgrade pip >/dev/null || true
}

# ---------------------------------- Core logic -------------------------------------------
detect_django() {
  local is_django="0"
  if [[ -f "${PROJECT_DIR}/manage.py" ]]; then
    is_django="1"
  elif compgen -G "${PROJECT_DIR}/requirements*.txt" >/dev/null && \
       grep -iEqs '(^|\s)django(==|>=|~=|>|<|$)' "${PROJECT_DIR}"/requirements*.txt; then
    is_django="1"
  elif [[ -f "${PROJECT_DIR}/pyproject.toml" ]] && grep -iqs 'django' "${PROJECT_DIR}/pyproject.toml"; then
    is_django="1"
  elif [[ -f "${PROJECT_DIR}/Pipfile.lock" ]] && grep -iqs '"django":' "${PROJECT_DIR}/Pipfile.lock"; then
    is_django="1"
  fi

  if [[ "${is_django}" == "1" ]]; then
    log_message "INFO" "Django project detected."
  else
    log_message "WARN" "No clear Django indicators found. Continuing audit anyway…"
  fi
}

resolve_dependencies() {
  log_message "INFO" "Resolving dependencies to a pinned requirements file…"
  if [[ "${DRY_RUN}" == true ]]; then
    log_message "INFO" "[DRY RUN] Would resolve and write to: ${REQS_TXT}"
    return 0
  fi

  # Prefer requirements*.txt
  if compgen -G "${PROJECT_DIR}/requirements*.txt" >/dev/null; then
    local candidate
    if [[ -f "${PROJECT_DIR}/requirements.txt" ]]; then
      candidate="${PROJECT_DIR}/requirements.txt"
    else
      candidate="$(ls "${PROJECT_DIR}"/requirements*.txt | head -n1)"
    fi
    log_message "INFO" "Using requirements file: $(basename "${candidate}")"
    cp "${candidate}" "${REQS_TXT}"

  # Poetry
  elif [[ -f "${PROJECT_DIR}/pyproject.toml" || -f "${PROJECT_DIR}/poetry.lock" ]]; then
    log_message "INFO" "Poetry project detected; exporting lock to requirements…"
    python -m pip install "poetry>=1.6" >/dev/null
    (cd "${PROJECT_DIR}" && poetry export --without-hashes -f requirements.txt -o "${REQS_TXT}") \
      || log_message "CRITICAL" "Poetry export failed."

  # Pipenv
  elif [[ -f "${PROJECT_DIR}/Pipfile.lock" || -f "${PROJECT_DIR}/Pipfile" ]]; then
    log_message "INFO" "Pipenv project detected; exporting lock to requirements…"
    python -m pip install pipenv >/dev/null
    (cd "${PROJECT_DIR}" && pipenv lock -r > "${REQS_TXT}") \
      || log_message "CRITICAL" "Pipenv export failed."
  else
    log_message "CRITICAL" "Could not find requirements*.txt, Poetry, or Pipenv definitions."
  fi

  if ! grep -qE '^[a-zA-Z0-9_.-]+' "${REQS_TXT}"; then
    log_message "CRITICAL" "Resolved requirements file appears empty: ${REQS_TXT}"
  fi

  if grep -iq '^django[<>= ]' "${REQS_TXT}" 2>/dev/null; then
    local djv
    djv=$(grep -i '^django[<>= ]' "${REQS_TXT}" | head -n1 | sed 's/[Dd]jango[[:space:]]*//')
    log_message "WARN" "Django pinned constraint detected: ${djv}"
  else
    log_message "WARN" "Django not explicitly pinned in resolved requirements. Consider pinning an LTS."
  fi
}

install_audit_tools() {
  if [[ "${DRY_RUN}" == true ]]; then
    log_message "INFO" "[DRY RUN] Would install: pip-audit${SKIP_PIP_AUDIT:+ (skipped)}, safety${SKIP_SAFETY:+ (skipped)}"
    return 0
  fi

  local tools=()
  [[ "${SKIP_PIP_AUDIT}" == false ]] && tools+=("pip-audit")
  [[ "${SKIP_SAFETY}" == false ]] && tools+=("safety")

  if ((${#tools[@]} > 0)); then
    python -m pip install "${tools[@]}" >/dev/null || log_message "CRITICAL" "Failed to install audit tools"
  else
    log_message "CRITICAL" "Both scanners skipped. Nothing to do."
  fi
}

run_pip_audit() {
  [[ "${SKIP_PIP_AUDIT}" == true ]] && { log_message "INFO" "Skipping pip-audit"; return 0; }
  if [[ "${DRY_RUN}" == true ]]; then
    log_message "INFO" "[DRY RUN] Would run pip-audit on ${REQS_TXT} -> ${PIP_AUDIT_JSON}"
    return 0
  fi
  log_message "INFO" "Running pip-audit…"
  set +e
  pip-audit --vulnerability-service=osv -r "${REQS_TXT}" --progress-spinner off --format json > "${PIP_AUDIT_JSON}"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    log_message "INFO" "pip-audit: no known vulnerabilities (exit 0)."
  else
    log_message "WARN" "pip-audit reported vulnerabilities (non‑zero exit)."
  fi
}

run_safety() {
  [[ "${SKIP_SAFETY}" == true ]] && { log_message "INFO" "Skipping Safety"; return 0; }
  if [[ "${DRY_RUN}" == true ]]; then
    log_message "INFO" "[DRY RUN] Would run Safety on ${REQS_TXT} -> ${SAFETY_JSON} (min severity: ${FAIL_ON_SEVERITY})"
    return 0
  fi
  log_message "INFO" "Running Safety…"
  set +e
  safety check --file "${REQS_TXT}" --full-report --json --min-severity "${FAIL_ON_SEVERITY}" > "${SAFETY_JSON}"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    log_message "INFO" "Safety: no vulnerabilities at or above '${FAIL_ON_SEVERITY}'."
  else
    log_message "WARN" "Safety reported vulnerabilities (≥ ${FAIL_ON_SEVERITY})."
  fi
}

summarize_and_decide() {
  if [[ "${DRY_RUN}" == true ]]; then
    log_message "INFO" "[DRY RUN] Would summarize findings and decide exit code."
    return 0
  fi
  log_message "INFO" "Summarizing results…"

  # Capture OK/FAIL token from Python, and write a human summary file.
  local token
  token="$(python - "$FAIL_ON_SEVERITY" "$PIP_AUDIT_JSON" "$SAFETY_JSON" "$SUMMARY_TXT" <<'PY'
import json, os, sys, re

fail_threshold = sys.argv[1].lower()
pip_audit_path = sys.argv[2]
safety_path    = sys.argv[3]
summary_path   = sys.argv[4]

sev_map = {"low":1,"medium":2,"high":3,"critical":4}
fail_rank = sev_map.get(fail_threshold, 1)

# ---------- helpers ----------
def normalize_sev(s):
    if not s: return None
    s = str(s).strip().lower()
    if s in {"moderate", "mod"}: return "medium"
    if s in {"low","medium","high","critical"}: return s
    return None

def first_float_in_text(text):
    if text is None: return None
    m = re.search(r"(?:^|[^0-9])([0-9]+(?:\.[0-9]+)?)", str(text))
    if not m: return None
    try:
        val = float(m.group(1))
        if 0.0 <= val <= 10.0:
            return val
    except Exception:
        pass
    return None

def cvss_to_level(score):
    if score is None: return None
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0:  return "low"
    return None

def extract_first_cvss(obj):
    # Walk any JSON and return the first plausible base score (0..10)
    if isinstance(obj, dict):
        # Common direct fields
        for k in ("cvss", "cvss_v3", "cvssv3", "score"):
            if k in obj:
                sc = first_float_in_text(obj.get(k))
                if sc is not None:
                    return sc
        # Nested walk
        for v in obj.values():
            sc = extract_first_cvss(v)
            if sc is not None:
                return sc
    elif isinstance(obj, list):
        for it in obj:
            sc = extract_first_cvss(it)
            if sc is not None:
                return sc
    elif isinstance(obj, str):
        sc = first_float_in_text(obj)
        if sc is not None:
            return sc
    return None

def osv_severity(vuln):
    # 1) Direct string severity (rare)
    sev = normalize_sev(vuln.get("severity"))
    if sev: return sev

    # 2) OSV "severity" list (type + score), prefer numeric score if found
    sev_list = vuln.get("severity")
    if isinstance(sev_list, list) and sev_list:
        # Some tools put dicts with 'score' as "7.8" or a vector string; extract number
        for ent in sev_list:
            sc = first_float_in_text(ent.get("score"))
            if sc is not None:
                sev = cvss_to_level(sc)
                if sev: return sev

    # 3) database_specific.severity (e.g., GHSA: LOW/MODERATE/HIGH/CRITICAL)
    ds_sev = normalize_sev((vuln.get("database_specific") or {}).get("severity"))
    if ds_sev: return ds_sev

    # 4) Any CVSS-like numbers anywhere in the vuln object
    sc = extract_first_cvss(vuln)
    if sc is not None:
        sev = cvss_to_level(sc)
        if sev: return sev

    return None

def rank_of(sev):
    return sev_map.get(normalize_sev(sev) or "low", 1)

found = []
lines = []

# Build lookups from Safety so we can borrow severities by ID or package
safety_by_id = {}
safety_by_pkg = {}

if os.path.isfile(safety_path) and os.path.getsize(safety_path) > 0:
    try:
        raw_safety = json.load(open(safety_path, "r", encoding="utf-8"))
        issues = raw_safety if isinstance(raw_safety, list) else raw_safety.get("issues", [])
        for it in issues:
            sev = normalize_sev(it.get("severity"))
            if not sev:
                # try infer from any cvss-ish field if present
                sc = extract_first_cvss(it)
                sev = cvss_to_level(sc) if sc is not None else None
            if not sev:
                sev = "low"  # final fallback: never unknown
            # Index by known IDs
            for key in filter(None, [it.get("cve"), it.get("ghsa_id"), it.get("advisory_id")]):
                safety_by_id[str(key)] = sev
            # Index by package
            dep = (it.get("package_name") or "").lower()
            if dep:
                safety_by_pkg.setdefault(dep, []).append(sev)
    except Exception:
        pass

# Parse pip-audit (OSV) JSON
if os.path.isfile(pip_audit_path) and os.path.getsize(pip_audit_path) > 0:
    try:
        data = json.load(open(pip_audit_path, "r", encoding="utf-8"))
        deps = data.get("dependencies", [])
        findings = []
        for pkg in deps:
            for v in pkg.get("vulns", []):
                sev = normalize_sev(v.get("severity"))
                if not sev:
                    sev = osv_severity(v)
                # Borrow severity from Safety by ID aliases (GHSA/CVE) if still missing
                if not sev:
                    for key in [v.get("id"), *(v.get("aliases") or [])]:
                        key = str(key) if key else None
                        if key and key in safety_by_id:
                            sev = safety_by_id[key]
                            break
                # Borrow by package max severity if still missing
                if not sev:
                    pkgname = (pkg.get("name") or "").lower()
                    sevs = safety_by_pkg.get(pkgname) or []
                    if sevs:
                        order = {"low":1,"medium":2,"high":3,"critical":4}
                        sev = max(sevs, key=lambda x: order.get(x,0))
                # Final fallback: never "unknown"
                if not sev:
                    sev = "low"

                fix = v.get("fix_versions") or []
                fix_str = ", ".join(fix) if isinstance(fix, list) else (fix or "-")

                findings.append({
                    "tool":"pip-audit","pkg":pkg.get("name"),"ver":pkg.get("version"),
                    "id":v.get("id"),"sev":sev,"fix":fix_str or "-"
                })

        if findings:
            lines.append("=== pip-audit findings ===")
            for f in findings:
                lines.append(f"- {f['pkg']}=={f['ver']} | {f['id']} | severity={f['sev']} | fix={f['fix']}")
                if rank_of(f["sev"]) >= fail_rank:
                    found.append(("pip-audit", f))
            lines.append("")
        else:
            lines.append("pip-audit: no findings.")
    except Exception as e:
        lines.append(f"pip-audit: failed to parse JSON: {e}")

# Parse Safety JSON
if os.path.isfile(safety_path) and os.path.getsize(safety_path) > 0:
    try:
        raw = json.load(open(safety_path, "r", encoding="utf-8"))
        issues = raw if isinstance(raw, list) else raw.get("issues", [])
        if issues:
            lines.append("=== Safety findings ===")
            for it in issues:
                dep  = it.get("package_name")
                ver  = it.get("installed_version")
                sev  = normalize_sev(it.get("severity"))
                if not sev:
                    sc = extract_first_cvss(it)
                    sev = cvss_to_level(sc) if sc is not None else None
                if not sev:
                    sev = "low"  # ensure no "unknown"

                cve  = it.get("cve") or (it.get("ghsa_id") or "-")
                fix  = it.get("fixed_versions")
                fixs = ", ".join(fix) if isinstance(fix, list) else (fix or "-")
                adv  = (it.get("advisory") or "").strip().splitlines()[0:1]
                advs = adv[0] if adv else ""
                lines.append(f"- {dep}=={ver} | {cve} | severity={sev} | fix={fixs} | {advs}")
                if rank_of(sev) >= fail_rank:
                    found.append(("safety", it))
            lines.append("")
        else:
            lines.append("Safety: no findings.")
    except Exception as e:
        lines.append(f"Safety: failed to parse JSON: {e}")

with open(summary_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines).strip()+"\n")

print("FAIL" if found else "OK")
PY
)"
  echo "---------- SUMMARY (brief) ----------"
  [[ -f "${SUMMARY_TXT}" ]] && sed -n '1,200p' "${SUMMARY_TXT}" || true
  echo "-------------------------------------"

  if [[ "${token}" == "FAIL" ]]; then
    log_message "ERROR" "Vulnerabilities found at or above threshold '${FAIL_ON_SEVERITY}'."
    return 1
  fi

  log_message "INFO" "No vulnerabilities meeting/exceeding threshold '${FAIL_ON_SEVERITY}'."
  return 0
}

main() {
  log_message "INFO" "Auditing: ${PROJECT_DIR}"
  log_message "INFO" "Output dir: ${OUTPUT_DIR}"
  log_message "INFO" "Fail threshold: ${FAIL_ON_SEVERITY}"
  [[ "${SKIP_PIP_AUDIT}" == true ]] && log_message "INFO" "pip-audit: SKIPPED"
  [[ "${SKIP_SAFETY}" == true ]] && log_message "INFO" "Safety: SKIPPED"

  detect_django
  resolve_dependencies
  install_audit_tools

  if [[ "${DRY_RUN}" == true ]]; then
    log_message "INFO" "[DRY RUN] Skipping scanners."
    return 0
  fi

  run_pip_audit
  run_safety
  summarize_and_decide
}

# ---------------------------------- Execution flow ---------------------------------------
parse_params "$@"
init_artifacts
validate_inputs
prepare_environment
main || {
  log_message "ERROR" "Artifacts:"
  [[ -f "${PIP_AUDIT_JSON}" ]] && log_message "ERROR" " - ${PIP_AUDIT_JSON}"
  [[ -f "${SAFETY_JSON}"   ]] && log_message "ERROR" " - ${SAFETY_JSON}"
  [[ -f "${SUMMARY_TXT}"   ]] && log_message "ERROR" " - ${SUMMARY_TXT}"
  exit 1
}

log_message "INFO" "Artifacts:"
[[ -f "${PIP_AUDIT_JSON}" ]] && log_message "INFO" " - ${PIP_AUDIT_JSON}"
[[ -f "${SAFETY_JSON}"   ]] && log_message "INFO" " - ${SAFETY_JSON}"
[[ -f "${SUMMARY_TXT}"   ]] && log_message "INFO" " - ${SUMMARY_TXT}"
log_message "INFO" "Done."
exit 0

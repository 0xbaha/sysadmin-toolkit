#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT
#
# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : upgrade_django_project.sh
# PURPOSE       : Safely upgrade a Django project across supported version hops using
#                 conservative steps: per-hop installs, codemods, sanity checks, and
#                 optional tests/migrations. Leaves the original requirements intact and
#                 writes a reviewed output file with suggested pins.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-10-26
# LAST UPDATED  : 2025-10-26
# VERSION       : 1.0.0
# =========================================================================================
#
# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script assists with upgrading Django projects through safe, incremental hops:
#   3.2 → 4.0 → 4.2 → 5.0 → 5.1 → 5.2.7 (LTS as of authoring).
#
# Key features:
# - Creates a temporary virtual environment to isolate installs.
# - Installs each target hop and applies django-upgrade codemods per hop.
# - Runs manage.py check and optionally runs tests (auto-detected or forced).
# - Optionally handles pending migrations (create/apply) via --auto-makemigrations.
# - Automatically replaces django-q with django-q2 when entering Django 5.x.
# - Writes requirements.upgraded.txt with Django==5.2.7 and safe minimums for peers
#   (asgiref, sqlparse, djangorestframework, whitenoise, redis, etc.).
# - Produces UPGRADE_NOTES_DJANGO_5.txt with post-upgrade guidance and reminders.
# - Original requirements.txt is NOT modified; work happens on copies.
#
# Workflow (high-level):
# 1) Validate paths and Python interpreter; create fresh venv.
# 2) For each hop: install current env, adjust incompatible packages (e.g., django-q→django-q2),
#    install target Django version, run codemods, run checks/tests, handle migrations.
# 3) Emit upgraded requirements and concise upgrade notes for manual review.
# =========================================================================================
#
# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - Conservative: prefer incremental hops and minimal, well-known companion bumps.
# - Isolated: use an ephemeral venv; avoid polluting developer or system environments.
# - Non-destructive: do not edit the original requirements file; output a new one.
# - Practical: apply codemods and basic lint fixes to reduce manual toil.
# - Guardrails: sanity checks, optional test runs, and migration prompts to reduce risk.
# =========================================================================================
#
# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Django maintainers and backend engineers upgrading legacy or LTS projects.
# - DevOps/Platform engineers supporting application upgrade campaigns.
# =========================================================================================
#
# =========================================================================================
# USAGE
# =========================================================================================
# Permissions:
#   chmod +x ./upgrade_django_project.sh
#
# Syntax:
#   ./upgrade_django_project.sh \
#       [--requirements PATH] [--project-root PATH] [--python PYBIN] \
#       [--venv PATH] [--run-tests auto|yes|no] [--keep-venv] \
#       [--dry-run] [--pip-flags "..."] [--auto-makemigrations] [--ruff-unsafe] \
#       [-h|--help]
#
# Examples:
#   ./upgrade_django_project.sh --requirements requirements.txt --project-root .
#   ./upgrade_django_project.sh --dry-run --pip-flags "--index-url=https://pypi.org/simple"
#   ./upgrade_django_project.sh --auto-makemigrations --run-tests yes --ruff-unsafe
#
# Notes:
# - Dry-run performs installs per hop but skips codemods/tests; still useful to validate
#   resolver behavior before applying code changes.
# - Final outputs include requirements.upgraded.txt and UPGRADE_NOTES_DJANGO_5.txt.
# =========================================================================================
#
# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# - Place the script in the repository (e.g., ./scripts/) or a directory in PATH.
# - Make it executable (chmod +x).
# - Commit changes on a feature branch; run in a throwaway environment if possible.
# =========================================================================================
#
# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# Required interpreter:
# - /usr/bin/env bash (Bash 4+ recommended)
#
# System tools:
# - python3 with venv module, coreutils, grep, awk, sed, find, git (optional)
#
# Python packages (installed inside the ephemeral venv):
# - pip, wheel, setuptools, pip-tools
# - django-upgrade (codemods), ruff (optional auto-fixes)
#
# Python compatibility:
# - Django 5.2 expects Python 3.10–3.13; the script emits a warning otherwise.
# =========================================================================================
#
# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# - Human-readable progress to stdout/stderr. Review the on-screen output and the generated
#   upgrade notes. For additional logging, pipe output to a file when invoking the script.
# =========================================================================================
#
# =========================================================================================
# OUTPUTS
# =========================================================================================
# - requirements.upgraded.txt     : Proposed pins after successful hops (keeps original intact)
# - UPGRADE_NOTES_DJANGO_5.txt    : Post-upgrade notes, risks, and follow-ups
# - Temporary virtual environment : Removed by default unless --keep-venv is set
# =========================================================================================
#
# =========================================================================================
# ERROR HANDLING & EXIT CODES
# =========================================================================================
# - set -Eeuo pipefail is enabled; most failures abort the script early.
# - Exit codes (best-effort as behavior can vary by failure site):
#   0: Success
#   1: Django checks/tests failed during a hop
#   2: Argument/validation errors (e.g., missing files/paths) or early safety abort
# =========================================================================================
#
# =========================================================================================
# SECURITY & SAFETY CONSIDERATIONS
# =========================================================================================
# - Network access: pip installs occur for each hop; honor corporate index/proxy via --pip-flags.
# - Code changes: codemods and optional ruff fixes alter Python files. Commit on a branch,
#   review diffs, and run your test suite/linters/formatters afterwards.
# - Migrations: enabling --auto-makemigrations will create/apply migrations; review carefully.
# - Idempotency: running multiple times is generally safe on a clean branch; always version-control
#   changes and validate before merging/deploying.
# =========================================================================================
#
# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Executed within a Django project (manage.py present) or with --project-root pointing to one.
# - Requirements are resolvable for each hop; some third-party packages may need manual pins.
# - For projects using django-q, migrating to django-q2 improves Django 5.x compatibility.
# =========================================================================================

set -Eeuo pipefail
shopt -s nullglob globstar

# --- SAFETY NOTICE ---
if [[ $# -eq 0 ]]; then
  echo "=============================================================="
  echo " ⚠️  WARNING: No arguments provided!"
  echo "--------------------------------------------------------------"
  echo " This script performs Django version upgrades and can modify:"
  echo "   • Python virtual environments"
  echo "   • Installed packages and dependencies"
  echo "   • Your project codebase (codemods and migrations)"
  echo ""
  echo " To avoid accidental damage, the script will not run without arguments."
  echo ""
  echo " Example safe usage:"
  echo "   ./upgrade_django_project.sh --dry-run"
  echo "   ./upgrade_django_project.sh --requirements requirements.txt --project-root ."
  echo ""
  echo " Read the documentation or use '--help' for details."
  echo "=============================================================="
  exit 2
fi
# --- END SAFETY NOTICE ---

# ---------------------------------------------
# Django 3.2.x -> 5.2.7 LTS Upgrade Helper
# - Safe version hops: 3.2 -> 4.0 -> 4.2 -> 5.0 -> 5.1 -> 5.2.7
# - Optional --dry-run: skips codemods & tests; still installs per hop
# - Creates a throwaway venv and writes requirements.upgraded.txt
# - Runs manage.py check (always), tests (optional)
# ---------------------------------------------

# Defaults (override with flags)
REQ_FILE="requirements.txt"
PROJECT_ROOT="."
PYBIN="python3"
VENV_DIR=".venv-django-upgrade"
RUN_TESTS="auto"   # auto | yes | no
RUFF_UNSAFE="no"   # yes | no
EXTRA_PIP_FLAGS=""
KEEP_VENV="no"
DRY_RUN="no"
AUTO_MAKEMIGRATIONS="no"   # yes | no

usage() {
  cat <<-USAGE
  Usage: $0 [--requirements PATH] [--project-root PATH] [--python PYBIN]
            [--venv PATH] [--run-tests auto|yes|no] [--keep-venv]
            [--dry-run] [--pip-flags "..."]
            [--auto-makemigrations]  # create & apply missing migrations automatically
            [--ruff-unsafe]  # enable ruff unsafe fixes (optional; off by default)
            [-h|--help]

  Examples:
    $0 --requirements requirements.txt --project-root . --auto-makemigrations --ruff-unsafe
    $0 --dry-run --pip-flags "--index-url=https://pypi.org/simple"

  Notes:
   - Writes: requirements.upgraded.txt (review and pin as needed)
   - Leaves original requirements.txt untouched
   - --dry-run skips codemods and tests; still performs per-hop installs
USAGE
}

# --- arg parse ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --requirements) REQ_FILE="$2"; shift 2 ;;
    --project-root) PROJECT_ROOT="$2"; shift 2 ;;
    --python) PYBIN="$2"; shift 2 ;;
    --venv) VENV_DIR="$2"; shift 2 ;;
    --run-tests) RUN_TESTS="$2"; shift 2 ;;
    --ruff-unsafe) RUFF_UNSAFE="yes"; shift 1 ;;
    --pip-flags) EXTRA_PIP_FLAGS="$2"; shift 2 ;;
    --keep-venv) KEEP_VENV="yes"; shift 1 ;;
    --dry-run) DRY_RUN="yes"; shift 1 ;;
    --auto-makemigrations) AUTO_MAKEMIGRATIONS="yes"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

# --- sanity checks ---
if [[ ! -f "$REQ_FILE" ]]; then
  echo "ERR: requirements file not found at: $REQ_FILE" >&2
  exit 2
fi
if [[ ! -d "$PROJECT_ROOT" ]]; then
  echo "ERR: project root not found at: $PROJECT_ROOT" >&2
  exit 2
fi

pushd "$PROJECT_ROOT" >/dev/null

# --- detect manage.py ---
MANAGE=""
if [[ -f "manage.py" ]]; then
  MANAGE="$PWD/manage.py"
fi

# --- detect current Django pin ---
current_django="$(grep -Ei '^[[:space:]]*django==[0-9]+' "$REQ_FILE" | head -n1 | tr -d ' ' | cut -d= -f3 || true)"
if [[ -z "${current_django}" ]]; then
  echo "WARN: Could not detect a strict Django pin in $REQ_FILE (e.g. Django==3.2.25)."
else
  echo "INFO: Detected Django==$current_django in $REQ_FILE"
fi

# --- Python version check ---
if ! command -v "$PYBIN" >/dev/null 2>&1; then
  echo "ERR: Python interpreter not found: $PYBIN" >&2
  exit 2
fi
py_ver="$($PYBIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
major_minor="$($PYBIN -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
echo "INFO: Using $PYBIN ($py_ver)"

$PYBIN - <<'PY' || true
import sys
maj,min= sys.version_info[:2]
ok = (maj==3 and 10 <= min <= 13)
if not ok:
    print(f"WARN: Django 5.2 expects Python 3.10–3.13; you have {sys.version.split()[0]}.", flush=True)
PY

# --- create venv (fresh) ---
if [[ -d "$VENV_DIR" ]]; then
  echo "INFO: Removing existing venv: $VENV_DIR"
  rm -rf "$VENV_DIR"
fi
"$PYBIN" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip wheel setuptools $EXTRA_PIP_FLAGS

# tools (ruff/django-upgrade only used if not dry-run)
python -m pip install "pip-tools>=7.4" $EXTRA_PIP_FLAGS
if [[ "$DRY_RUN" == "no" ]]; then
  python -m pip install "django-upgrade>=1.28.0" "ruff>=0.6.0" $EXTRA_PIP_FLAGS
fi

# --- copy requirements to a working file we can mutate in-memory ---
WORK_REQ="$(mktemp -t req.XXXXXXXX.txt)"
cp "$REQ_FILE" "$WORK_REQ"

# Also prepare an output upgraded file
OUT_REQ="requirements.upgraded.txt"
cp "$REQ_FILE" "$OUT_REQ"

echo "INFO: Working on copy: $WORK_REQ"
echo "INFO: Final upgraded requirements will be written to: $OUT_REQ"

# --- detect django-related packages from the ORIGINAL requirements ---
mapfile -t DJANGO_PACKAGES < <(grep -Eio '^[[:space:]]*django[-_.a-z0-9]+' "$REQ_FILE" \
  | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//' \
  | awk '{print tolower($0)}' \
  | sort -u)

# Remember if the project used django-q (swap to django-q2 later if needed)
USED_DJANGO_Q=$(printf '%s\n' "${DJANGO_PACKAGES[@]}" | grep -E "^django-q$" || true)

# --- begin helpers ---
# --- helper: set/replace a requirement line to a spec ---
set_req_pin() {
  local pkg="$1" spec="$2" file="$3"
  if grep -Eiq "^[[:space:]]*${pkg}([[:space:]]*==|[[:space:]]*>=|[[:space:]]*~=|[[:space:]]*<=)" "$file"; then
    sed -E -i.bak "s|^[[:space:]]*(${pkg})([[:space:]]*([<>=!~]=)?[^#]*)?([[:space:]]*#.*)?$|\\1${spec}|I" "$file"
  else
    echo "${pkg}${spec}" >> "$file"
  fi
}

# --- helper: remove a pkg from requirements file (case-insensitive) ---
remove_req_pkg() {
  local pkg="$1" file="$2"
  # delete lines that start with the package name (with optional version/comments)
  sed -E -i.bak "/^[[:space:]]*${pkg}([[:space:]]*([<>=!~]=)?[^#]*)?([[:space:]]*#.*)?$/Id" "$file"
}

# --- helper: ensure a pkg spec exists in requirements (append if missing) ---
ensure_req_pkg() {
  local pkg="$1" spec="$2" file="$3"
  if ! grep -Eiq "^[[:space:]]*${pkg}([[:space:]]*([<>=!~]=)?[^#]*)?" "$file"; then
    echo "${pkg}${spec}" >> "$file"
  fi
}

# --- helper: case-insensitive exact-line dedupe (keeps first occurrence) ---
dedupe_exact_lines_ci() {
  local file="$1"
  awk 'BEGIN{IGNORECASE=1}!seen[tolower($0)]++' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# --- helper: prefer exact (==) pins over ">=" suggestions for the same package ---
prefer_exact_over_min() {
  local file="$1" pkg
  for pkg in "${!SUGGEST_MIN[@]}"; do
    # if an exact pin exists, drop any non-exact spec lines (>=, <=, ~=, !=) for that pkg
    if grep -Eiq "^[[:space:]]*${pkg}[[:space:]]*==[0-9]" "$file"; then
      sed -E -i.bak "/^[[:space:]]*${pkg}[[:space:]]*(>=|<=|~=|!=)/Id" "$file"
    fi
  done
}

# --- helper: keep the correct app label for django-q2 (module stays 'django_q') ---
normalize_django_q_app_label() {
  for f in settings.py **/settings.py; do
    [[ -f "$f" ]] || continue
    # if someone changed to 'django_q2' in INSTALLED_APPS, switch it back
    sed -i.bak -E "s/(['\"])django_q2(['\"])|(['\"])django-q2(['\"])/'django_q'/g" "$f"
  done
}

# --- helper: detect and optionally create/apply pending migrations ---
handle_pending_migrations() {
  # Preconditions
  [[ -z "$MANAGE" ]] && return 0
  [[ "$DRY_RUN" == "yes" ]] && return 0

  local out rc
  # --check exits non-zero if migrations are needed; --dry-run prints the diff
  set +e
  out="$(python "$MANAGE" makemigrations --check --dry-run 2>&1)"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    echo "INFO: Pending migrations detected."
    # Show a short preview (first 40 lines) to aid debugging
    echo "$out" | sed -n '1,40p'

    if [[ "$AUTO_MAKEMIGRATIONS" == "yes" ]]; then
      echo "INFO: --auto-makemigrations enabled -> creating migrations..."
      # Non-interactive creation and apply
      python "$MANAGE" makemigrations --noinput
      python "$MANAGE" migrate
    else
      echo "WARN: Migrations are required but were not created."
      echo "      Run: $VENV_DIR/bin/python $MANAGE makemigrations && $VENV_DIR/bin/python $MANAGE migrate"
    fi
  fi
}
# --- end helpers ---

# --- compatibility nudges (non-destructive; pinned minimally) ---
declare -A SUGGEST_MIN=(
  [Django]="==5.2.7"
  [asgiref]=">=3.8.1"
  [sqlparse]=">=0.5.0"
  [djangorestframework]=">=3.16.0"
  [whitenoise]=">=6.6.0"
  [redis]=">=4.5.0"
)
NEEDS_PYTZ_WARN="no"
grep -Eiq '^[[:space:]]*pytz([[:space:]]*==|[[:space:]]*>=|[[:space:]]*~=|[[:space:]]*<=)' "$REQ_FILE" && NEEDS_PYTZ_WARN="yes"

RISKY=()
grep -Eiq '^[[:space:]]*django-q([[:space:]]*==|[[:space:]]*>=|[[:space:]]*~=|[[:space:]]*<=)' "$REQ_FILE" && RISKY+=("django-q (often incompatible with Django 5.x). Consider django-q2 / django-rq / Celery.")

# --- the upgrade hops ---
HOPS=("4.0.*" "4.2.*" "5.0.*" "5.1.*" "5.2.7")

run_checks() {
  if [[ -z "$MANAGE" ]]; then
    echo "INFO: manage.py not found; skipping Django checks/tests."
    return 0
  fi
  echo "INFO: Running Django system checks..."
  python "$MANAGE" check || { echo "ERR: 'manage.py check' failed"; return 1; }

  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "INFO: Dry-run mode: skipping tests."
    return 0
  fi

  if [[ "$RUN_TESTS" == "no" ]]; then
    echo "INFO: Skipping tests by request."
    return 0
  fi
  if [[ "$RUN_TESTS" == "auto" ]]; then
    if compgen -G "tests/**" >/dev/null || compgen -G "**/*_tests.py" >/dev/null || compgen -G "**/tests.py" >/dev/null; then
      echo "INFO: Running test suite (auto)..."
      python -Wall -Wa "$MANAGE" test || { echo "ERR: tests failed"; return 1; }
    else
      echo "INFO: No tests detected; skipping."
    fi
  else
    echo "INFO: Running test suite..."
    python -Wall -Wa "$MANAGE" test || { echo "ERR: tests failed"; return 1; }
  fi
}

apply_codemods() {
  local target="$1"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "INFO: Dry-run mode: skipping codemods for target $target."
    return 0
  fi
  echo "INFO: Applying django-upgrade codemods for target Django $target ..."

  # Prefer git-tracked files when available (respects repo root & excludes venvs)
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # enumerate only tracked *.py files
    git ls-files -z -- '*.py' \
      | xargs -0 -r django-upgrade --target-version "$target"
  else
    # fallback: find every *.py (skip common virtualenvs and the temp venv)
    find . -type f -name '*.py' \
      -not -path "./$VENV_DIR/*" \
      -not -path "./venv/*" \
      -not -path "./.venv/*" \
      -print0 \
      | xargs -0 -r django-upgrade --target-version "$target"
  fi

  # Optional: light auto-fixes (safe + optional unsafe)
  if command -v ruff >/dev/null 2>&1; then
    local unsafe=()
    [[ "$RUFF_UNSAFE" == "yes" ]] && unsafe+=(--unsafe-fixes)
    ruff check --select UP,PIE,COM,ISC --fix "${unsafe[@]}" .
  fi
}

for hop in "${HOPS[@]}"; do
  echo "=============================="
  echo ">>> Upgrading Django to: $hop"
  echo "=============================="

  # If we've already switched to django-q2, relax Django so resolver can proceed
  if grep -Eiq '^[[:space:]]*django-?q2' "$WORK_REQ"; then
    set_req_pin "Django" ">=4.2" "$WORK_REQ"
  fi

  # Install current env
  python -m pip install -r "$WORK_REQ" $EXTRA_PIP_FLAGS

  # If entering 5.x, auto-replace django-q with django-q2 BEFORE installing Django 5
  if [[ "$hop" == 5.* ]]; then
    # Is django_q present?
    if python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('django_q') else 1)" >/dev/null 2>&1; then
      HAS_DQ=1
    else
      HAS_DQ=0
    fi

    if [[ $HAS_DQ -eq 1 ]]; then
      echo "INFO: Replacing django-q -> django-q2 for Django $hop ..."
      # 1) Uninstall/install in the current venv
      python -m pip uninstall -y django-q || true
      python -m pip install "django-q2>=1.8,<2" $EXTRA_PIP_FLAGS

      # 2) Update requirements working copy and the final output
      remove_req_pkg "django-?q" "$WORK_REQ"
      ensure_req_pkg "django-q2" ">=1.8,<2" "$WORK_REQ"
      remove_req_pkg "django-?q" "$OUT_REQ"
      ensure_req_pkg "django-q2" ">=1.8,<2" "$OUT_REQ"

      # 3) Update INSTALLED_APPS
      normalize_django_q_app_label

      # 4) Optionally migrate (non-dry-run only)
      if [[ -n "$MANAGE" && "$DRY_RUN" == "no" ]]; then
        echo "INFO: Running 'manage.py migrate' after django-q2 swap..."
        python "$MANAGE" migrate || echo "WARN: migrate had issues; review later."
        # Check if that migrate revealed pending model changes
        handle_pending_migrations
      else
        echo "INFO: Dry-run or no manage.py: skipping migrate."
      fi
    fi
  fi

  # Now install the Django hop
  python -m pip install "Django==${hop}" --upgrade --upgrade-strategy eager $EXTRA_PIP_FLAGS

  # Codemods for the hop
  case "$hop" in
    4.0.*) apply_codemods "4.0" ;;
    4.2.*) apply_codemods "4.2" ;;
    5.0.*) apply_codemods "5.0" ;;
    5.1.*) apply_codemods "5.1" ;;
    5.2.7) apply_codemods "5.2" ;;
  esac

  # Checks/tests
  run_checks

  # Surface & optionally auto-fix pending migrations for this hop
  handle_pending_migrations
done

# --- Finalize: write an upgraded requirements file suggestion ---
# One last migration sanity pass before finalizing output
handle_pending_migrations
echo "INFO: Writing $OUT_REQ with Django==5.2.7 and suggested mins for common peers..."

# 1) Ensure only one canonical Django line
remove_req_pkg "Django" "$OUT_REQ"   # capitalized
remove_req_pkg "django" "$OUT_REQ"   # lowercase variant
echo "Django==5.2.7" >> "$OUT_REQ"

# 2) Append suggested minimums without clobbering existing exact pins
for pkg in "${!SUGGEST_MIN[@]}"; do
  spec="${SUGGEST_MIN[$pkg]}"
  # If an exact pin already exists in OUT_REQ, keep it; otherwise add the suggestion
  if grep -Eiq "^[[:space:]]*${pkg}[[:space:]]*==[0-9]" "$OUT_REQ"; then
    : # exact pin present -> do nothing
  else
    set_req_pin "$pkg" "$spec" "$OUT_REQ"
  fi
done

# --- ensure detected django add-ons are NOT removed, and are (minimally) upgraded ---

# If the project used django-q, replace with django-q2 (Django 5+ compatibility)
if [[ -n "$USED_DJANGO_Q" ]]; then
  remove_req_pkg "django-?q" "$OUT_REQ" || true
  set_req_pin "django-q2" ">=1.6.0" "$OUT_REQ"
  normalize_django_q_app_label || true
  # Update the tracked list so guards below apply to django-q2
  DJANGO_PACKAGES=($(printf '%s\n' "${DJANGO_PACKAGES[@]}" | grep -v '^django-q$'; echo django-q2 | sort -u))
fi

# Keep/re-add every detected django-* package from the original file.
for pkg in "${DJANGO_PACKAGES[@]}"; do
  # Already present in OUT_REQ? Keep as-is.
  if grep -Eiq "^[[:space:]]*${pkg}([[:space:]]*([<>=!~]=)?[^#]*)?[[:space:]]*(#.*)?$" "$OUT_REQ"; then
    continue
  fi

  # Missing? re-add with a safe minimum (specific floors for common add-ons; generic fallback otherwise)
  case "$pkg" in
    django-crispy-forms) set_req_pin "$pkg" ">=2.1.0" "$OUT_REQ" ;;
    django-axes)         set_req_pin "$pkg" ">=7.0.2" "$OUT_REQ" ;;
    django-extensions)   set_req_pin "$pkg" ">=3.2.3" "$OUT_REQ" ;;
    django-imagekit)     set_req_pin "$pkg" ">=5.0.0" "$OUT_REQ" ;;
    django-picklefield)  set_req_pin "$pkg" ">=3.2" "$OUT_REQ" ;;
    django-widget-tweaks)set_req_pin "$pkg" ">=1.5.0" "$OUT_REQ" ;;
    django-appconf)      set_req_pin "$pkg" ">=1.1.0" "$OUT_REQ" ;;
    django-auditlog)     set_req_pin "$pkg" ">=3.0.0" "$OUT_REQ" ;;
    django-upgrade)      set_req_pin "$pkg" ">=1.28.0" "$OUT_REQ" ;;
    *)                   set_req_pin "$pkg" ">=1.0.0" "$OUT_REQ" ;;
  esac
done

# 3) If both exact pin and >= suggestion ended up present for any reason, keep exact
prefer_exact_over_min "$OUT_REQ"

# 4) Final pass: remove any remaining exact duplicate lines (case-insensitive)
dedupe_exact_lines_ci "$OUT_REQ"

# --- Sort alphabetically (case-insensitive), preserving a *leading* header (comments/blank lines) if present ---
#     Django (core) → django-* → other django... (no hyphen)
# Detect whether the first non-empty line is a comment (=> we have a header block)
if awk 'BEGIN{h=0} /^[[:space:]]*$/ {next} /^[[:space:]]*#/ {h=1; exit} {h=0; exit} END{exit h?0:1}' "$OUT_REQ"; then
  # Split header and package body
  awk -v hdr="$OUT_REQ.header" -v pk="$OUT_REQ.pkgs" '
    BEGIN { in_hdr = 1 }
    {
      if (in_hdr) {
        if ($0 ~ /^[[:space:]]*($|#)/) { print > hdr; next }
        in_hdr = 0
      }
      print > pk
    }
  ' "$OUT_REQ"

  # Global case-insensitive sort of packages
  sort -f "$OUT_REQ.pkgs" > "$OUT_REQ.pkgs.all"

  # Reorder the contiguous django block: Django → django-* → other django...
  awk '
    function flush_django_block(   i) {
      # 1) Django core first
      for (i=0;i<corec;i++) print core[i]
      # 2) django-* next (already globally sorted)
      for (i=0;i<hc;i++)    print h[i]
      # 3) other django... last (already globally sorted)
      for (i=0;i<oc;i++)    print o[i]
      corec=hc=oc=0
    }
    {
      line=$0; low=tolower(line)
      is_dj_core = (low ~ /^django($|[[:space:]]|==)/)
      is_dj_hyp  = (low ~ /^django-/)
      is_dj_any  = (low ~ /^django/)
      if (is_dj_any) {
        if (!in_dj) in_dj=1
        if (is_dj_core) { core[corec++]=line; next }
        else if (is_dj_hyp) { h[hc++]=line; next }
        else { o[oc++]=line; next }
      }
      # leaving django block -> flush it before printing non-django line
      if (in_dj) { flush_django_block(); in_dj=0 }
      print line
    }
    END{
      if (in_dj) { flush_django_block() }
    }
  ' "$OUT_REQ.pkgs.all" > "$OUT_REQ.pkgs.sorted"

  # Stitch header + sorted body
  cat "$OUT_REQ.header" "$OUT_REQ.pkgs.sorted" > "$OUT_REQ.sorted"
  mv "$OUT_REQ.sorted" "$OUT_REQ"
  rm -f "$OUT_REQ.header" "$OUT_REQ.pkgs" "$OUT_REQ.pkgs.all" "$OUT_REQ.pkgs.sorted"
else
  # No header: same logic directly on the file
  sort -f "$OUT_REQ" > "$OUT_REQ.all"
  awk '
    function flush_django_block(   i) {
      for (i=0;i<corec;i++) print core[i]
      for (i=0;i<hc;i++)    print h[i]
      for (i=0;i<oc;i++)    print o[i]
      corec=hc=oc=0
    }
    {
      line=$0; low=tolower(line)
      is_dj_core = (low ~ /^django($|[[:space:]]|==)/)
      is_dj_hyp  = (low ~ /^django-/)
      is_dj_any  = (low ~ /^django/)
      if (is_dj_any) {
        if (!in_dj) in_dj=1
        if (is_dj_core) { core[corec++]=line; next }
        else if (is_dj_hyp) { h[hc++]=line; next }
        else { o[oc++]=line; next }
      }
      if (in_dj) { flush_django_block(); in_dj=0 }
      print line
    }
    END{
      if (in_dj) { flush_django_block() }
    }
  ' "$OUT_REQ.all" > "$OUT_REQ.sorted"
  mv "$OUT_REQ.sorted" "$OUT_REQ"
  rm -f "$OUT_REQ.all"
fi

UPGRADE_NOTES="UPGRADE_NOTES_DJANGO_5.txt"
{
  echo "Django Upgrade Notes"
  echo "===================="
  echo "- Processed hops up to Django 5.2.7."
  echo "- Review $OUT_REQ and adjust pins as needed."
  echo
  echo "Important follow-ups:"
  echo "1) CSRF_TRUSTED_ORIGINS must include scheme, e.g., https://example.com"
  echo "2) Replace deprecated APIs removed in Django 4.0+ (ugettext, force_text, is_ajax, NullBooleanField, contrib.postgres.JSONField)."
  echo "3) Time zones: prefer zoneinfo; avoid pytz-only APIs."
  echo "4) If using Redis cache/session: Django's built-in RedisCache expects 'redis' Python package >= 4.x."
  [[ "${NEEDS_PYTZ_WARN}" == "yes" ]] && echo "5) pytz is still in requirements. Keep only if truly needed."
  if ((${#RISKY[@]})); then
    echo
    echo "Potential blockers:"
    for item in "${RISKY[@]}"; do echo "- $item"; done
  fi
  echo
  echo "Testing & deployment:"
  echo "- Run: $VENV_DIR/bin/python manage.py check --deploy"
  echo "- Rebuild containers if applicable; run migrations; smoke test admin & auth flows."
  [[ "$DRY_RUN" == "yes" ]] && echo "- You ran --dry-run. Re-run without --dry-run to apply codemods."
} > "$UPGRADE_NOTES"

echo "INFO: Created $OUT_REQ"
echo "INFO: Notes written to $UPGRADE_NOTES"

# --- wrap up ---
deactivate || true
if [[ "$KEEP_VENV" != "yes" ]]; then
  rm -rf "$VENV_DIR"
  echo "INFO: Removed temporary venv ($VENV_DIR). Use --keep-venv to retain."
fi

echo "SUCCESS: Upgrade steps finished.
- Review: $OUT_REQ
- Read:   $UPGRADE_NOTES
- Next:   Create a branch, commit changes, and re-run without --dry-run when ready."

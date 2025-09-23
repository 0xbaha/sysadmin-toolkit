#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT
#
# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : upgrade_django_dependencies.sh
# PURPOSE       : Safely upgrades pinned Django project dependencies based on audit findings.
#                 Prefers same-major version fixes, allows major version bumps only if explicitly requested.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-09-23
# LAST UPDATED  : 2025-09-23
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script:
# - Reads a vulnerability summary file (pip-audit or similar).
# - Reads pinned requirements (==) from a requirements.txt file.
# - Generates an upgrade plan preferring highest patch/minor within same major.
# - Allows optional major upgrades with `--allow-major`.
# - Produces human-readable and machine-readable plan outputs.
# - Optionally applies upgrades in a virtual environment and runs validation checks.
#
# Exit Codes:
#   0 - OK, plan created (and applied if requested) without hard errors.
#   2 - Plan created but requires manual review; no apply performed.
#   3 - Apply step failed (install/tests). Review required.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
#   ./upgrade_django_dependencies.sh \
#       --summary SUMMARY.txt \
#       --requirements requirements.txt \
#       --out-dir ./upgrade_out \
#       [--apply] [--allow-major] \
#       [--venv .venv] [--manage-py ./manage.py] \
#       [--extra-test "pytest -q"]
#
# Example (plan only):
#   ./upgrade_django_dependencies.sh --summary output/summary.txt --requirements requirements.txt
#
# Example (apply with major upgrades allowed):
#   ./upgrade_django_dependencies.sh --summary output/summary.txt --requirements requirements.txt --apply --allow-major
# =========================================================================================

# -----------------------------------------------------------------------------------------
# Strict mode & runtime basics (adapted from your template)
# -----------------------------------------------------------------------------------------
set -euo pipefail
# set -x   # enable via -d

# Defaults
SUMMARY_FILE=""
REQS_FILE="requirements.txt"
OUT_DIR="./upgrade_out"
APPLY=0
ALLOW_MAJOR=0
VENV_PATH=""
MANAGE_PY=""
EXTRA_TEST_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary) SUMMARY_FILE="$2"; shift 2;;
    --requirements) REQS_FILE="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --apply) APPLY=1; shift;;
    --allow-major) ALLOW_MAJOR=1; shift;;
    --venv) VENV_PATH="$2"; shift 2;;
    --manage-py) MANAGE_PY="$2"; shift 2;;
    --extra-test) EXTRA_TEST_CMD="$2"; shift 2;;
    -h|--help)
      sed -n '1,120p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

if [[ -z "$SUMMARY_FILE" ]] || [[ ! -f "$SUMMARY_FILE" ]]; then
  echo "[ERR] --summary file is required and must exist" >&2
  exit 1
fi

if [[ ! -f "$REQS_FILE" ]]; then
  echo "[ERR] requirements file not found: $REQS_FILE" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

PLAN_JSON="$OUT_DIR/upgrade_plan.json"
PLAN_TXT="$OUT_DIR/upgrade_plan.txt"
CONSTRAINTS_TXT="$OUT_DIR/constraints.upgrade.txt"
LOG_APPLY="$OUT_DIR/apply.log"

# Phase 1: Build a plan (Python does the heavy lifting)
python3 - "$SUMMARY_FILE" "$REQS_FILE" "$PLAN_JSON" "$PLAN_TXT" "$CONSTRAINTS_TXT" "$ALLOW_MAJOR" <<'PY'
import sys, json, re, os
from collections import defaultdict
try:
    from packaging.version import Version, InvalidVersion
except Exception:
    # Allow plan generation without packaging (only basic parsing). We'll try best-effort.
    class Version(str):
        def __new__(cls, v):
            return str.__new__(cls, v)
        @property
        def major(self):
            try:
                return int(str(self).split('.')[0])
            except:
                return 0
        def __lt__(self, other): return str(self) < str(other)
        def __le__(self, other): return str(self) <= str(other)
        def __gt__(self, other): return str(self) > str(other)
        def __ge__(self, other): return str(self) >= str(other)
    InvalidVersion = Exception

summary_path, reqs_path, plan_json, plan_txt, constraints_txt, allow_major = sys.argv[1:7]
allow_major = int(allow_major)

# Parse requirements (only pinned lines pkg==ver, ignore comments/extras)
pins = {}
req_lines = []
with open(reqs_path, 'r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        req_lines.append(line.rstrip('\n'))
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)==([^\s#;]+)', line_stripped)
        if m:
            pkg, ver = m.group(1), m.group(2)
            pins[pkg.lower()] = {'name': pkg, 'version': ver}

# Parse summary lines like:
# - package==X | VULN-ID | severity=... | fix=1.2.3, 2.0.0
vulns = defaultdict(list)
with open(summary_path, 'r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        s = line.strip()
        if not s.startswith('- ') or ' | ' not in s:
            continue
        # Extract
        m = re.match(r'^- ([A-Za-z0-9_.\-]+)==([^\s|]+)\s*\|\s*([^|]+)\|\s*severity=([^|]+)\|\s*fix=([^\n]*)', s.replace(' |', '|'))
        if not m:
            # Try more permissive split
            try:
                body = s[2:]
                left, vulnid, sevpart, fixpart = [x.strip() for x in body.split('|')]
                pkg, ver = [y.strip() for y in left.split('==',1)]
                sev = sevpart.split('=',1)[1].strip()
                fix = fixpart.split('=',1)[1].strip()
            except Exception:
                continue
        else:
            pkg, ver, vulnid, sev, fix = m.groups()
            sev = sev.strip()
            fix = fix.strip()

        if pkg.lower() not in pins:
            # not in our pinned reqs; skip
            continue

        # Fix versions: can be '-', a single version, or CSV
        fixes = []
        if fix and fix != '-':
            for tok in re.split(r'[,\s]+', fix):
                tok = tok.strip().strip(',')
                if tok:
                    # Strip non-version suffixes
                    tok = tok.strip()
                    fixes.append(tok)
        vulns[pkg.lower()].append({
            'pkg': pkg, 'current': pins[pkg.lower()]['version'],
            'vuln_id': vulnid, 'severity': sev.lower(), 'fixes': fixes
        })

# Helper: choose a target version
def choose_target(current: str, fixes: list[str], allow_major: bool):
    """
    Given current version and a list of recommended fixes,
    return (target_version, rationale, same_major_ok, residual_fix_ids)
    - Picks a single target that meets as many fix minima as possible
    - Prefers highest fix that still shares the same major as current
    - If none shares same major:
        * if allow_major: pick the minimal fix among list
        * else: return (current, 'manual_review', False, [list_of_vuln_ids_that_need_major])
    """
    try:
        cur = Version(current)
    except InvalidVersion:
        # If unparsable, fallback: return the max textual fix if not crossing rough major
        if not fixes:
            return current, "no_fixes_listed", True, []
        # naive: pick lexicographically highest fix with same leading number
        cur_major = current.split('.')[0]
        same_major = [f for f in fixes if f.split('.')[0] == cur_major]
        if same_major:
            same_major.sort()
            return same_major[-1], "same_major_max", True, []
        if allow_major:
            fixes_sorted = sorted(fixes, key=lambda x: [int(p) if p.isdigit() else p for p in re.split(r'[^\d]+', x) if p!=''])
            return fixes_sorted[0], "allow_major_min", False, []
        return current, "manual_review", False, fixes

    # Normalize fix versions to Version, keep mapping
    valid = []
    for f in fixes:
        try:
            valid.append((Version(f), f))
        except InvalidVersion:
            continue
    if not valid:
        return current, "no_valid_fix_versions", True, []

    # Same-major candidates
    same = [(v, raw) for (v, raw) in valid if v.major == cur.major]
    if same:
        # choose the HIGHEST same-major fix
        same.sort(key=lambda x: x[0])
        best_v, best_raw = same[-1]
        return best_raw, "same_major_max", True, []

    # No same-major
    if allow_major:
        # choose the MINIMUM overall to reduce breaking risk
        valid.sort(key=lambda x: x[0])
        min_v, min_raw = valid[0]
        return min_raw, "allow_major_min", False, []
    else:
        # require manual review
        return current, "manual_review", False, [raw for (_, raw) in valid]

plan = {}
manual_review_needed = False

for pkg_key, items in vulns.items():
    current = pins[pkg_key]['version']
    pkgname = pins[pkg_key]['name']

    # aggregate all fix versions listed across vulns
    all_fixes = []
    for it in items:
        for f in it['fixes']:
            if f not in all_fixes:
                all_fixes.append(f)

    target, rationale, same_major_ok, residual = choose_target(current, all_fixes, allow_major=allow_major)

    # When we choose same-major target, some CVEs might still require higher major.
    # We'll flag them as residual_risk if their minimum fix is greater than target.
    residual_ids = []
    try:
        tgtV = Version(target)
    except Exception:
        tgtV = None

    for it in items:
        # if an item has any fix > target, we consider it residual
        need_higher = False
        for f in it['fixes']:
            try:
                if tgtV is not None and Version(f) > tgtV:
                    need_higher = True
                    break
            except InvalidVersion:
                continue
        if need_higher:
            residual_ids.append(it['vuln_id'])

    entry = {
        'package': pkgname,
        'current': current,
        'target': target,
        'allow_major': bool(allow_major),
        'rationale': rationale,
        'residual_risk_vulns': sorted(set(residual_ids))
    }
    plan[pkgname] = entry
    if rationale == "manual_review" or residual_ids:
        manual_review_needed = True

# Write plan.json
with open(plan_json, 'w', encoding='utf-8') as fh:
    json.dump({'plan': plan, 'notes': {
        'policy': 'prefer same-major fixes; allow major bumps only with --allow-major',
        'manual_review_needed': manual_review_needed
    }}, fh, indent=2, ensure_ascii=False)

# Write plan.txt (human-readable) and constraints
lines = []
cons = []
for pkg in sorted(plan.keys(), key=str.lower):
    e = plan[pkg]
    annot = f"{e['package']}=={e['target']}   # current={e['current']} rationale={e['rationale']} allow_major={e['allow_major']}"
    if e['residual_risk_vulns']:
        annot += f" residual_risk={','.join(e['residual_risk_vulns'])}"
    lines.append(annot)
    cons.append(f"{e['package']}=={e['target']}")

with open(plan_txt, 'w', encoding='utf-8') as fh:
    fh.write("# SAFE UPGRADE PLAN (conservative)\n")
    fh.write("# Policy: prefer highest patch/minor within same major. Use --allow-major to permit major bumps.\n")
    fh.write("# Each line shows target pin and rationale. Review any residual_risk entries.\n\n")
    fh.write("\n".join(lines) + "\n")

with open(constraints_txt, 'w', encoding='utf-8') as fh:
    fh.write("# constraints for safe upgrade install\n")
    fh.write("\n".join(cons) + "\n")

# Exit code to indicate manual review
if manual_review_needed and not allow_major:
    # Signal that the plan was created but manual review is suggested
    # The driver script will not fail; it will return code 2 (handled outside Python)
    pass
PY

# Capture manual review signal via presence of 'residual_risk' markers
if grep -q "residual_risk=" "$PLAN_TXT"; then
  MANUAL_REVIEW=1
else
  MANUAL_REVIEW=0
fi

echo "[INFO] Plan written:"
echo "  - $PLAN_TXT"
echo "  - $CONSTRAINTS_TXT"
echo "  - $PLAN_JSON"

if [[ "$APPLY" -eq 0 ]]; then
  if [[ "$MANUAL_REVIEW" -eq 1 ]]; then
    echo "[WARN] Manual review recommended (some CVEs require major bump). Re-run with --allow-major if acceptable."
    exit 2
  fi
  exit 0
fi

# Phase 2: Apply the plan in a venv and run checks
if [[ -z "$VENV_PATH" ]]; then
  VENV_PATH="$OUT_DIR/venv"
fi

# Guard against set -u (nounset) and ensure paths exist
: "${OUT_DIR:=./upgrade_out}"
mkdir -p "$OUT_DIR"

# These should already be set earlier in the script, but make them robust:
: "${REQS_FILE:?missing --requirements file path}"
: "${CONSTRAINTS_TXT:=$OUT_DIR/constraints.upgrade.txt}"

# Predeclare files we will write so they’re not “unbound” when referenced
RELAXED="$OUT_DIR/requirements.relaxed.txt"
EXTRA_CONS="$OUT_DIR/constraints.extra.txt"
> "$RELAXED"; : > "$EXTRA_CONS"


echo "[INFO] Creating/using venv: $VENV_PATH"
python3 -m venv "$VENV_PATH"
. "$VENV_PATH/bin/activate"

#######################################################...

# --- REPLACE the existing awk block that writes $RELAXED with this ---
awk '
  # Robust parser:
  # - trims leading spaces
  # - strips inline comments after "#"
  # - matches pins with == or === (full package token, not just first char)
  # - ignores include lines (-r/-c/--requirement/--constraint)
  function strip_comment(s,    i) {
    i = index(s, "#"); return (i>0) ? substr(s,1,i-1) : s
  }
  BEGIN { OFS="" }
  FNR==NR {
    line=$0
    sub(/^[[:space:]]+/,"",line)
    line=strip_comment(line)
    if (match(line, /^([A-Za-z0-9_.-]+)[[:space:]]*={2,3}/, m)) {
      c[tolower(m[1])]=1
    }
    next
  }
  {
    raw=$0
    line=$0
    sub(/^[[:space:]]+/,"",line)
    # keep comments/blank
    if (line ~ /^[#]|^$/) { print raw; next }
    # keep include lines
    if (line ~ /^-[rc]\b/ || line ~ /^--(requirement|constraint)\b/) { print raw; next }
    # parse (without trailing comment)
    parse=strip_comment(line)
    if (match(parse, /^([A-Za-z0-9_.-]+)[[:space:]]*={2,3}/, m)) {
      pkg=tolower(m[1])
      if (pkg in c) { print m[1]; next }  # drop exact pin so constraints win
    }
    print raw
  }
' "$CONSTRAINTS_TXT" "$REQS_FILE" > "$RELAXED"

# Safety net: if any package appears in constraints and is STILL pinned in $RELAXED, unpin it.
while read -r name; do
  [ -z "$name" ] && continue
  if grep -qiE "^[[:space:]]*$name[[:space:]]*==|^[[:space:]]*$name[[:space:]]*===" "$RELAXED"; then
    echo "[WARN] Still pinned in relaxed file -> $name ; forcibly unpinning." | tee -a "$LOG_APPLY"
    sed -i -E "s#^([[:space:]]*)($name)([[:space:]]*)==[^[:space:]]+#\\1\\2#gI" "$RELAXED"
    sed -i -E "s#^([[:space:]]*)($name)([[:space:]]*)===.*#\\1\\2#gI" "$RELAXED"
  fi
done < <(awk 'BEGIN{IGNORECASE=1}
  /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*={2,3}/ {
    s=$0; sub(/^[[:space:]]+/,"",s);
    split(s,a,"="); n=tolower(a[1]); gsub(/[[:space:]]*/,"",n); print n
  }' "$CONSTRAINTS_TXT")

 

# --- BEGIN REPLACE: build EFFECTIVE constraints instead of stacking extras ---
# Build an "effective" constraints file starting from the plan, then adjust DRF once (no conflicts).
EFFECTIVE_CONS="$OUT_DIR/constraints.effective.txt"
cp "$CONSTRAINTS_TXT" "$EFFECTIVE_CONS"

# Detect pinned Django target from plan constraints
DJANGO_PIN="$(awk '
  BEGIN{IGNORECASE=1}
  /^[[:space:]]*django==/{
    sub(/^[[:space:]]*/,"",$0);
    split($0,a,"=="); print a[2]; exit
  }
' "$CONSTRAINTS_TXT")"

# If Django target < 4.2, force DRF to the last compatible (3.14.x) by rewriting the plan constraint
if [[ -n "$DJANGO_PIN" ]]; then
  MJ="${DJANGO_PIN%%.*}"
  REST="${DJANGO_PIN#*.}"
  MN="${REST%%.*}"
  if [[ "$MJ" =~ ^[0-9]+$ && "$MN" =~ ^[0-9]+$ ]]; then
    if (( MJ < 4 )) || { (( MJ == 4 )) && (( MN < 2 )); }; then
      # Remove any DRF pins from the plan constraints…
      sed -i -E '/^[[:space:]]*djangorestframework[[:space:]]*==/Id' "$EFFECTIVE_CONS"
      # …and pin explicitly to a compatible version (adjust if you prefer another 3.14.x)
      echo 'djangorestframework==3.14.0' >> "$EFFECTIVE_CONS"
      echo "[INFO] Using DRF==3.14.0 because Django target is ${DJANGO_PIN} (<4.2)" | tee -a "$LOG_APPLY"
    fi
  fi
fi
# --- END REPLACE ---



# --- BEGIN REPLACE INSTALL ---
echo "[INFO] Installing with relaxed requirements + effective constraints..."
python -m pip install -r "$RELAXED" -c "$EFFECTIVE_CONS" >>"$LOG_APPLY" 2>&1
# --- END REPLACE INSTALL ---

#######################################################...

echo "[INFO] Running pip check..."
python -m pip check | tee -a "$LOG_APPLY"

echo "[INFO] Byte-compiling all Python files (sanity) ..."
python -m compileall -q . || true

# Django sanity check if manage.py supplied or found
if [[ -n "$MANAGE_PY" ]]; then
  if [[ -f "$MANAGE_PY" ]]; then
    echo "[INFO] Django system check (--deploy) ..."
    python "$MANAGE_PY" check --deploy | tee -a "$LOG_APPLY" || true
  else
    echo "[WARN] manage.py not found at: $MANAGE_PY"
  fi
else
  if [[ -f "manage.py" ]]; then
    echo "[INFO] Django system check (--deploy) ..."
    python manage.py check --deploy | tee -a "$LOG_APPLY" || true
  fi
fi

# Optional extra tests from user
if [[ -n "$EXTRA_TEST_CMD" ]]; then
  echo "[INFO] Running extra tests: $EXTRA_TEST_CMD"
  bash -lc "$EXTRA_TEST_CMD" | tee -a "$LOG_APPLY" || true
fi

# Re-audit quickly if available
if command -v pip-audit >/dev/null 2>&1; then
  echo "[INFO] Running pip-audit (quick) ..."
  pip-audit -r "$REQS_FILE" -c "$CONSTRAINTS_TXT" --progress-spinner off | tee -a "$LOG_APPLY" || true
fi

echo "[INFO] Freeze to $OUT_DIR/requirements.post-upgrade.txt"
python -m pip freeze > "$OUT_DIR/requirements.post-upgrade.txt"

echo "[INFO] Apply step complete. See $LOG_APPLY for logs."
if [[ "$MANUAL_REVIEW" -eq 1 && "$ALLOW_MAJOR" -eq 0 ]]; then
  echo "[WARN] Residual risk remains (major bump needed for some CVEs). Consider --allow-major or manual testing."
fi

exit 0

#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Select OSS-Fuzz projects for the coverage-pipeline skill.
#
# Usage:
#   select_projects.sh [options] PATTERN [PATTERN ...]
#
# PATTERNs are shell globs matched against project directory names under
# projects/ — e.g. 'lib*', '*xml*', 'json-c', or '*' for all projects.
#
# Options:
#   --broken               only projects whose most recent public build
#                          failed (build regressions; needs network)
#   --include-never-built  with --broken: also include projects that have
#                          never built successfully (new/incomplete)
#   --limit N              output at most N projects (default: unlimited)
#   --exclude GLOBS        comma-separated name globs to drop, e.g. 'curl,*xml*'
#   -h, --help             show this help
#
#   --language LIST        comma-separated languages to keep, e.g. 'c,c++'
#                          or 'python' (default: all languages)
#
# Always applied:
#   - project must exist locally under projects/ with a project.yaml
#   - a missing language field counts as 'c++' (the legacy OSS-Fuzz default)
#
# Output: "project<TAB>language" per line, sorted and de-duplicated. A
# summary line goes to stderr. Exits 1 when nothing matches.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSS_FUZZ_ROOT="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
PROJECTS_DIR="$OSS_FUZZ_ROOT/projects"
STATUS_URL='https://oss-fuzz-build-logs.storage.googleapis.com/status.json'

BROKEN=0
NEVER_BUILT=0
LIMIT=0
EXCLUDE=''
LANGS=''
PATTERNS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --broken) BROKEN=1 ;;
    --include-never-built) NEVER_BUILT=1 ;;
    --limit) LIMIT="${2:?--limit needs a value}"; shift ;;
    --exclude) EXCLUDE="${2:?--exclude needs a value}"; shift ;;
    --language) LANGS="${2:?--language needs a value}"; shift ;;
    -h|--help)
      awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print} NR>1 && !/^#/ {exit}' "$0"
      exit 0 ;;
    -*) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    *) PATTERNS+=("$1") ;;
  esac
  shift
done

if [ ${#PATTERNS[@]} -eq 0 ]; then
  echo "error: provide at least one pattern ('*' selects all)" >&2
  exit 2
fi

# Echo the project's normalized language (missing field = 'c++', the
# legacy OSS-Fuzz default). Returns 1 when project.yaml is missing.
project_language() {
  local yaml="$PROJECTS_DIR/$1/project.yaml" lang
  [ -f "$yaml" ] || return 1
  lang="$(sed -n 's/^language:[[:space:]]*//p' "$yaml" | head -1 \
      | tr -d "\"' \t\r" | tr '[:upper:]' '[:lower:]')"
  [ -n "$lang" ] || lang='c++'
  printf '%s\n' "$lang"
}

# True when LANG passes the --language filter (empty filter = all).
lang_wanted() {
  if [ -z "$LANGS" ]; then
    return 0
  fi
  local want
  # Unquoted expansion on purpose: split the comma list on whitespace.
  for want in ${LANGS//,/ }; do
    if [ "$want" = "$1" ]; then
      return 0
    fi
  done
  return 1
}

# True when NAME matches any of the globs passed after it.
matches_any() {
  local name="$1" pat
  shift
  for pat in "$@"; do
    # Unquoted on purpose: the argument is a glob pattern.
    case "$name" in
      $pat) return 0 ;;
    esac
  done
  return 1
}

# --- Gather candidates: local dirs matching a pattern, C/C++ only. --------
SELECTED=()
for dir in "$PROJECTS_DIR"/*/; do
  name="$(basename "$dir")"
  lang="$(project_language "$name")" || continue
  matches_any "$name" "${PATTERNS[@]}" || continue
  lang_wanted "$lang" || continue
  SELECTED+=("$name|$lang")
done

# --- Optional exclusions. ---------------------------------------------------
if [ -n "$EXCLUDE" ]; then
  IFS=',' read -r -a EX_GLOBS <<< "$EXCLUDE"
  FILTERED=()
  for entry in "${SELECTED[@]}"; do
    if ! matches_any "${entry%%|*}" "${EX_GLOBS[@]}"; then
      FILTERED+=("$entry")
    fi
  done
  SELECTED=("${FILTERED[@]+${FILTERED[@]}}")
fi

# --- Optional broken-build filter (public build status). -------------------
if [ "$BROKEN" -eq 1 ]; then
  echo "Fetching build status from: $STATUS_URL" >&2
  BROKEN_LIST="$(curl -fsSL --max-time 60 "$STATUS_URL" | python3 -c '
import json, sys
regressions_only = sys.argv[1] != "1"
status = json.load(sys.stdin)
for entry in status.get("projects", []):
    name = entry.get("name")
    history = entry.get("history") or []
    if not name or not history:
        continue
    latest = max(history, key=lambda h: h.get("finish_time", ""))
    if latest.get("success", True):
        continue
    if regressions_only and not entry.get("last_successful_build"):
        continue
    print(name)
' "$NEVER_BUILT")" || { echo "error: could not fetch/parse build status" >&2; exit 1; }
  FILTERED=()
  for entry in "${SELECTED[@]}"; do
    if printf '%s\n' "$BROKEN_LIST" | grep -qxF "${entry%%|*}"; then
      FILTERED+=("$entry")
    fi
  done
  SELECTED=("${FILTERED[@]+${FILTERED[@]}}")
fi

# --- Sort, cap, emit. -------------------------------------------------------
if [ ${#SELECTED[@]} -eq 0 ]; then
  echo 'No projects matched.' >&2
  exit 1
fi

LIST="$(printf '%s\n' "${SELECTED[@]}" | sort -u)"
COUNT="$(printf '%s\n' "$LIST" | grep -c .)"
if [ "$LIMIT" -gt 0 ] && [ "$LIMIT" -lt "$COUNT" ]; then
  LIST="$(printf '%s\n' "$LIST" | head -n "$LIMIT")"
  COUNT="$LIMIT"
fi

printf '%s\n' "$LIST" | sed 's/|/\t/'
SCOPE='project(s)'
if [ -n "$LANGS" ]; then
  SCOPE="$LANGS project(s)"
fi
if [ "$BROKEN" -eq 1 ]; then
  SCOPE="$SCOPE, broken builds only"
fi
echo "Selected $COUNT $SCOPE matching: ${PATTERNS[*]}" >&2

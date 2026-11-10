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
################################################################################

# Install the skills in this folder into an agent's skills directory.
#
# Usage:
#   ./copy_to_global.sh [target ...]
#
# Targets:
#   claude       -> ~/.claude/skills  (default when no target is given)
#   gemini       -> ~/.gemini/skills
#   <directory>  -> any other argument is used as the skills directory
#                   itself (created if missing; resolved relative to your
#                   current working directory). This works for any agent
#                   that reads SKILL.md-style skills, e.g. Cline's
#                   workspace directory:
#                       ./copy_to_global.sh /path/to/vscode-workspace/.cline/skills
#
# Multiple targets may be given in one invocation, e.g.:
#   ./copy_to_global.sh gemini claude /abs/path/.cline/skills
#
# Skills are auto-discovered: every directory next to this script that
# contains a SKILL.md is copied. Existing skills of the same name in the
# target directory are overwritten.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-discover the skills next to this script.
SKILLS=()
for entry in "$SCRIPT_DIR"/*/; do
  if [ -f "${entry}SKILL.md" ]; then
    SKILLS+=("$(basename "$entry")")
  fi
done
if [ ${#SKILLS[@]} -eq 0 ]; then
  echo "No skills found in $SCRIPT_DIR" >&2
  exit 1
fi

# Resolve a target name to a skills directory. Unknown names are treated as
# directory paths so that new agents work without script changes.
resolve_target() {
  case "$1" in
    gemini) echo "$HOME/.gemini/skills" ;;
    claude) echo "$HOME/.claude/skills" ;;
    *) echo "$1" ;;
  esac
}

# Default to claude when no target is given.
if [ $# -eq 0 ]; then
  set -- claude
fi

for target in "$@"; do
  GLOBAL_SKILLS_DIR="$(resolve_target "$target")"
  echo "Installing ${#SKILLS[@]} skills to: $GLOBAL_SKILLS_DIR"
  mkdir -p "$GLOBAL_SKILLS_DIR"
  for skill in "${SKILLS[@]}"; do
    # Replace any existing skill with the same name in the target directory.
    if [ -d "$GLOBAL_SKILLS_DIR/$skill" ]; then
      rm -rf "$GLOBAL_SKILLS_DIR/$skill"
    fi
    echo "  copying $skill"
    cp -r "$SCRIPT_DIR/$skill" "$GLOBAL_SKILLS_DIR/"
  done
done

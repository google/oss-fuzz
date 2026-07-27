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

# Copy the skills folder into the global skills directory

# Accept user input. Should by default be "gemini" but can be overridden by the user.
SKILLS_DIR=${1:-"gemini"}


# Gemini skills dir = ~/.gemini/skills
# Claude skills dir = ~/.claude/skills
if [ "$SKILLS_DIR" == "gemini" ]; then
  GLOBAL_SKILLS_DIR="$HOME/.gemini/skills"
elif [ "$SKILLS_DIR" == "claude" ]; then
  GLOBAL_SKILLS_DIR="$HOME/.claude/skills"
else
  echo "Invalid skills directory specified. Use 'gemini' or 'claude'."
  exit 1
fi

# Log target skill directory
echo "Copying skills to global skills directory: $GLOBAL_SKILLS_DIR"


# Now copy each of the skills from the local "skills" directory to the global skills directory
# Overwrite existing skills with the same name.
# Check if the global skills directory exists, if not create it
if [ ! -d "$GLOBAL_SKILLS_DIR" ]; then
  mkdir -p "$GLOBAL_SKILLS_DIR"
fi

# Copy each skill from the local "skills" directory to the global skills directory
# Make sure we work from this scripts base folder and copy each of the skills
# fuzzing-memory-unsafe-expert
# fuzzing-go-expert
# fuzzing-rust-expert
# fuzzing-jvm-expert
# fuzzing-python-expert
# oss-fuzz-engineer
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for skill in "fuzzing-memory-unsafe-expert" "fuzzing-go-expert" "fuzzing-rust-expert" "fuzzing-jvm-expert" "fuzzing-python-expert" "oss-fuzz-engineer"; do
  abs_skill="$SCRIPT_DIR/$skill"
  # Copy over the skill and replace any existing skill with the same name in the global skills directory
  if [ -d "$GLOBAL_SKILLS_DIR/$skill" ]; then
    rm -rf "$GLOBAL_SKILLS_DIR/$skill"
  fi

  echo "Copying $abs_skill to $GLOBAL_SKILLS_DIR/"
  cp -r "$abs_skill" "$GLOBAL_SKILLS_DIR/"
done

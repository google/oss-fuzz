#!/bin/bash -u
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
# Argument-handling test for rss_limit_mb forwarding in base-runner's
# `coverage` script (run_fuzz_target).
#
# Runs the real coverage script against a stub fuzz target with a controlled
# $OUT and asserts which libFuzzer flags it forwards:
#   1. .options with rss_limit_mb 4096        -> -rss_limit_mb=4096 forwarded
#   2. no .options file                       -> no -rss_limit_mb (default kept)
#   3. .options with only max_len             -> neither flag forwarded
#   4. rss_limit_mb + max_len                 -> only rss_limit_mb forwarded
#   5. malformed rss_limit_mb value           -> nothing forwarded
#
# The stub records its arguments and emulates an empty profile dump so
# run_fuzz_target's dump check returns early; the llvm-profdata/llvm-cov steps
# afterwards are expected to fail and their exit status is irrelevant here.
# Requires Linux (GNU timeout, nproc). Run from anywhere; it locates the
# sibling `coverage` and `parse_options.py` via this script's directory.

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"

fails=0

run_case() {
  local name="$1" options_content="$2" expect_rss_arg="$3"

  local tmp
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/out" "$tmp/corpus/stub_target" "$tmp/covout"

  cat > "$tmp/out/stub_target" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$STUB_ARGS_FILE"
p="${LLVM_PROFILE_FILE/\%1m/1}"
: > "$p"
exit 0
STUB
  chmod +x "$tmp/out/stub_target"

  if [ -n "$options_content" ]; then
    printf '%s\n' "$options_content" > "$tmp/out/stub_target.options"
  fi
  echo x > "$tmp/corpus/stub_target/input"

  env FUZZING_LANGUAGE=c++ FUZZING_ENGINE=none \
      PATH="$DIR:$PATH" \
      OUT="$tmp/out" COVERAGE_OUTPUT_DIR="$tmp/covout" \
      COVERAGE_EXTRA_ARGS="" CORPUS_DIR="$tmp/corpus" GOPATH="$tmp/go" \
      STUB_ARGS_FILE="$tmp/args" \
      timeout 120 "$DIR/coverage" stub_target \
      > "$tmp/coverage.log" 2>&1
  # Nonzero exit is expected (the llvm-profdata merge finds no .profdata);
  # only the forwarded arguments are under test.

  local got_rss="no" got_maxlen="no"
  if grep -qxF -- '-rss_limit_mb=4096' "$tmp/args" 2>/dev/null; then
    got_rss="yes"
  fi
  if grep -qxF -- '-max_len=4096' "$tmp/args" 2>/dev/null; then
    got_maxlen="yes"
  fi

  local ok="yes"
  if [ "$expect_rss_arg" = "present" ] && [ "$got_rss" = "no" ]; then
    ok="no"
  fi
  if [ "$expect_rss_arg" = "absent" ] && [ "$got_rss" = "yes" ]; then
    ok="no"
  fi
  if [ "$got_maxlen" = "yes" ]; then
    # max_len must never be forwarded to corpus replay.
    ok="no"
  fi
  if ! grep -qxF -- '-merge=1' "$tmp/args" 2>/dev/null; then
    # Existing behavior must be preserved.
    ok="no"
  fi

  if [ "$ok" = "yes" ]; then
    echo "PASS: $name (rss=$got_rss max_len=$got_maxlen)"
  else
    echo "FAIL: $name (rss=$got_rss max_len=$got_maxlen)"
    echo "--- forwarded args ---"
    cat "$tmp/args" 2>/dev/null || echo "(stub did not run)"
    echo "--- coverage log tail ---"
    tail -n 20 "$tmp/coverage.log" 2>/dev/null
    fails=$((fails + 1))
  fi
  rm -rf "$tmp"
}

run_case "options with rss_limit_mb" $'[libfuzzer]\nrss_limit_mb = 4096' "present"
run_case "no options file" "" "absent"
run_case "options with only max_len" $'[libfuzzer]\nmax_len = 4096' "absent"
run_case "options with rss_limit_mb and max_len" \
  $'[libfuzzer]\nrss_limit_mb = 4096\nmax_len = 4096' "present"
run_case "malformed rss_limit_mb value" \
  $'[libfuzzer]\nrss_limit_mb = 4096MB' "absent"

if [ "$fails" -ne 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"

#!/bin/bash -eu
# Copyright 2025 Google LLC.
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
#
# mruby's test suite runs in two batches, both of which report through
# test/assert.rb and therefore share one summary format:
#
#     Total: 2017
#        OK: 1998
#        KO: 0
#     Crash: 1
#   Warning: 0
#      Skip: 18
#
# "KO" is an assertion failure, "Crash" is a test body that raised an
# unexpected exception, and "Skip" is a test that opted out (18 of them need
# features this build does not enable, e.g. backtraces). Only KO and Crash mean
# something is wrong; test/assert.rb exits non-zero on exactly those two.
#
# This script parses those numbers instead of grepping for hard-coded counts,
# so it keeps working as upstream adds tests, and it tolerates a named list of
# pre-existing failures so that a failure introduced by a patch is still
# reported.
#
# This script only *runs* the tests, it deliberately does not rebuild them.
# Rebuilding after a patch is the job of build.sh / replay_build.sh, which run
# with the sanitizer flags in $CFLAGS. Those flags are added at runtime by
# OSS-Fuzz's `compile` and are not persisted into the Chronos cached image, so
# a rake invocation here that had to relink would fail on undefined __asan_*
# symbols. build.sh already builds the mrbtest driver (via `rake test`) and the
# mruby binaries the binary tests drive (via `rake all`), so both batches
# already reflect the patched sources by the time this runs.
#
# No network access is required or used.

# Pre-existing failures in mruby master that this script tolerates.
#
# Each entry is matched as a fixed string against the assertion report. The
# list is a tolerance, not an expectation: an entry that stops appearing does
# not fail this script, so upstream fixing one of these is not a breakage and
# the list only needs pruning for hygiene.
#
# 1. "inherited hook runs before class body" (test/t/class.rb) - every test
#    file shares one constant namespace inside the single mrbtest binary, and
#    test/t/module.rb already defines a top-level `class B` derived from
#    Object, so class.rb reopening it as `class B < A` raises
#    "TypeError: superclass mismatch for B". This is order-dependent constant
#    pollution in mruby's own test suite, unrelated to the fuzzing build.
KNOWN_FAILURES=(
  "inherited hook runs before class body"
)

# Floors on the number of passing tests per batch, not exact counts. They sit
# well below the current numbers (1998 and 105) so that adding tests upstream
# does not break this script, while a suite that dies early or silently stops
# running most of its tests is still caught.
LIB_MIN_OK=1900
BIN_MIN_OK=100

# mruby counts a test whose body ran but executed no assertion at all as a
# "Warn" and does not fail on it. Both batches currently report 0, and a patch
# that makes a test stop asserting is exactly the kind of silent regression
# Chronos needs to catch, so treat any warning as a failure. Raise this if
# upstream ever introduces a warning that is expected in this build.
MAX_WARNINGS=0

LIB_LOG=/tmp/mruby_test_lib.out
BIN_LOG=/tmp/mruby_test_bin.out

# The two batches are invoked separately instead of through `rake test`, which
# runs them as prerequisites of a single task: a failure in the library batch
# aborts rake before the binary batch ever starts, hiding anything the binary
# tests would have caught. Each batch's exit status is ignored here because the
# parsed summaries below are what decide the result.
(
cd $SRC/mruby
rake test:run:lib > "$LIB_LOG" 2>&1 || true
rake test:run:bin > "$BIN_LOG" 2>&1 || true
)

# Read a single "<field>: <number>" value out of a batch's summary block.
summary_field() {
  awk -v field="$2" '$0 ~ "^ *"field": [0-9]+$" {value=$NF} END {print value}' "$1"
}

# The assertion report lines describing failures, i.e. every reported line that
# is not a Skip or a Warn. Crash lines are prefixed with the exception class
# rather than a fixed marker, so they are identified by the trailing
# "(core)" / "(mrbgems: <gem>)" origin that assertion_string always appends.
failure_lines() {
  sed -n '1,/^ *Total: [0-9]*$/p' "$1" |
    grep -E '\((core|mrbgems: [^)]*)\)$' | grep -vE '^(Skip|Warn): ' || true
}

check_batch() {
  local name=$1 log=$2 min_ok=$3
  local total ok ko crash warning tolerated=0 failures pattern

  if [[ ! -s $log ]] || ! grep -qE '^ *Total: [0-9]+$' "$log"; then
    echo "FAIL [$name]: no test summary was produced, so the batch did not run"
    echo "             to completion (crashed or missing test driver)."
    return 1
  fi

  total=$(summary_field "$log" Total)
  ok=$(summary_field "$log" OK)
  ko=$(summary_field "$log" KO)
  crash=$(summary_field "$log" Crash)
  warning=$(summary_field "$log" Warning)

  if [[ ${#KNOWN_FAILURES[@]} -gt 0 ]]; then
    for pattern in "${KNOWN_FAILURES[@]}"; do
      if grep -qF "$pattern" "$log"; then
        tolerated=$((tolerated + 1))
      fi
    done
  fi
  failures=$((ko + crash))

  echo "[$name] Total: $total  OK: $ok  KO: $ko  Crash: $crash" \
       "Warning: $warning (tolerated pre-existing failures: $tolerated)"

  if [[ $warning -gt $MAX_WARNINGS ]]; then
    echo "FAIL [$name]: $warning test(s) executed no assertion, expected at most"
    echo "             $MAX_WARNINGS."
    sed -n '1,/^ *Total: [0-9]*$/p' "$log" | grep -E '^Warn: ' |
      sed 's/^/               /' || true
    return 1
  fi

  if [[ $ok -lt $min_ok ]]; then
    echo "FAIL [$name]: only $ok tests passed, expected at least $min_ok."
    echo "             Failing tests reported:"
    failure_lines "$log" | sed 's/^/               /'
    return 1
  fi

  # Any failure beyond the tolerated ones is a regression. Comparing the total
  # against the number of tolerated entries still present also covers the case
  # where a tolerated failure got fixed and a new one appeared in its place.
  if [[ $failures -ne $tolerated ]]; then
    echo "FAIL [$name]: $failures failing test(s) but only $tolerated tolerated."
    echo "             Failing tests reported:"
    failure_lines "$log" | sed 's/^/               /'
    return 1
  fi

  return 0
}

result=0
check_batch "library" "$LIB_LOG" "$LIB_MIN_OK" || result=1
check_batch "bintest" "$BIN_LOG" "$BIN_MIN_OK" || result=1

if [[ $result -ne 0 ]]; then
  # The batch output otherwise only exists in /tmp, which goes away with the
  # container, so surface enough of it to diagnose the failure.
  for log in "$LIB_LOG" "$BIN_LOG"; do
    echo "================ tail of $log ================"
    tail -40 "$log" 2>&1 || true
  done
  exit 1
fi

echo "mruby tests passed."

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
# "KO" is an assertion failure, "Crash" is a test body that raised an unexpected
# exception, "Warning" is a test body that ran but asserted nothing, and "Skip"
# is a test that opted out (some need features this build does not enable, e.g.
# backtraces). mruby itself exits non-zero on KO and Crash only.
#
# Nothing here hard-codes a test count. The counts above are illustrative; the
# script parses whatever the run reports and compares it against the baseline
# build.sh recorded from the pristine tree ($SRC/mruby_test_baseline, one
# "<batch> <passing> <problems>" line per batch). That baseline is regenerated
# every time the project image is built, so it tracks upstream as tests are
# added or removed, and it only has to be accurate within a single image, which
# is the window Chronos operates in. If the file is missing (an image built
# before this was introduced) the script falls back to the KNOWN_FAILURES list
# below and says so.
#
# This script only *runs* the tests, it deliberately does not rebuild them.
# Rebuilding after a patch is the job of build.sh / replay_build.sh, which run
# with the sanitizer flags in $CFLAGS. Those flags are added at runtime by
# OSS-Fuzz's `compile` and are not persisted into the Chronos cached image, so
# a rake invocation here that had to relink would fail on undefined __asan_*
# symbols. build.sh already builds the mrbtest driver and the mruby binaries
# the binary tests drive, so both batches reflect the patched sources already.
#
# No network access is required or used.

# Fallback tolerance, used only when no recorded baseline is available. Each
# entry is matched as a fixed string against the assertion report, and it is a
# tolerance rather than an expectation: an entry that stops appearing does not
# fail this script.
#
# 1. "inherited hook runs before class body" (test/t/class.rb) - every test file
#    shares one constant namespace inside the single mrbtest binary, and
#    test/t/module.rb already defines a top-level `class B` derived from Object,
#    so class.rb reopening it as `class B < A` raises "TypeError: superclass
#    mismatch for B". Order-dependent constant pollution in mruby's own test
#    suite, unrelated to the fuzzing build.
KNOWN_FAILURES=(
  "inherited hook runs before class body"
)

# How far the passing count may fall below the baseline before it is treated as
# a regression, as a percentage. This absorbs a test or two legitimately turning
# into a Skip in this build, while still catching a patch that stops a
# meaningful part of the suite from running at all. It is a ratio rather than an
# absolute count so it stays meaningful at any suite size.
PASS_FLOOR_PERCENT=90

BASELINE_FILE=${BASELINE_FILE:-$SRC/mruby_test_baseline}

# The rake tasks for the two batches. They are invoked separately instead of
# through `rake test`, which runs them as prerequisites of a single task: a
# failure in the library batch aborts rake before the binary batch ever starts,
# hiding anything the binary tests would have caught.
BATCHES=(lib bin)

declare -A BATCH_LOG=()
for batch in "${BATCHES[@]}"; do
  BATCH_LOG[$batch]=/tmp/mruby_test_${batch}.out
done

(
cd $SRC/mruby
for batch in "${BATCHES[@]}"; do
  # Exit status is deliberately ignored; the parsed summary is what decides.
  rake "test:run:${batch}" > "${BATCH_LOG[$batch]}" 2>&1 || true
done
)

# Read a single "<field>: <number>" value out of a batch's summary block.
summary_field() {
  awk -v field="$2" '$0 ~ "^ *"field": [0-9]+$" {value=$NF} END {print value+0}' "$1"
}

# The assertion report lines describing failures, i.e. every reported line that
# is not a Skip or a Warn. Crash lines are prefixed with the exception class
# rather than a fixed marker, so they are identified by the trailing "(core)" /
# "(mrbgems: <gem>)" origin that assertion_string always appends.
failure_lines() {
  sed -n '1,/^ *Total: [0-9]*$/p' "$1" |
    grep -E '\((core|mrbgems: [^)]*)\)$' | grep -vE '^(Skip|Warn): ' || true
}

# Look up a field of a batch's baseline line, empty when there is no baseline.
baseline_field() {
  [[ -r $BASELINE_FILE ]] || return 0
  awk -v batch="$1" -v col="$2" '$1 == batch {print $col}' "$BASELINE_FILE"
}

ran_any=0
result=0

check_batch() {
  local batch=$1 log=${BATCH_LOG[$1]}
  local total ok ko crash warning skip problems accounted
  local base_ok base_problems tolerated floor pattern source

  if grep -q "Don't know how to build task" "$log" 2>/dev/null; then
    # The task was renamed or removed upstream. No amount of parsing can adapt
    # to that, so fail loudly and name the task that needs updating rather than
    # silently testing nothing.
    echo "FAIL [$batch]: rake task 'test:run:$batch' no longer exists."
    echo "             mruby restructured its test tasks; update BATCHES."
    return 1
  fi

  if [[ ! -s $log ]] || ! grep -qE '[^[:space:]]' "$log"; then
    # The task exists but produced nothing, e.g. upstream disabled bintest for
    # this build config. Not a failure on its own; the check that at least one
    # batch ran covers the case where they all vanish.
    echo "[$batch] not enabled in this build, skipped."
    return 0
  fi

  if ! grep -qE '^ *Total: [0-9]+$' "$log"; then
    echo "FAIL [$batch]: the batch produced output but no summary, so it did"
    echo "             not run to completion (crashed test driver)."
    return 1
  fi

  ran_any=1
  total=$(summary_field "$log" Total)
  ok=$(summary_field "$log" OK)
  ko=$(summary_field "$log" KO)
  crash=$(summary_field "$log" Crash)
  warning=$(summary_field "$log" Warning)
  skip=$(summary_field "$log" Skip)

  # Every test must be accounted for in exactly one bucket. If this does not
  # hold, the report format changed and every number below is untrustworthy, so
  # refuse to pass rather than silently mis-parse a future format.
  accounted=$((ok + ko + crash + warning + skip))
  if [[ $total -ne $accounted ]]; then
    echo "FAIL [$batch]: summary does not add up ($ok+$ko+$crash+$warning+$skip"
    echo "             = $accounted, reported Total $total). The report format"
    echo "             changed; this script needs updating."
    return 1
  fi

  problems=$((ko + crash + warning))
  base_ok=$(baseline_field "$batch" 2)
  base_problems=$(baseline_field "$batch" 3)

  if [[ -n $base_ok && -n $base_problems ]]; then
    tolerated=$base_problems
    floor=$((base_ok * PASS_FLOOR_PERCENT / 100))
    source="baseline $base_ok passing / $base_problems pre-existing"
  else
    # No baseline: fall back to the hand-maintained list and do not police the
    # passing count, since there is nothing trustworthy to compare it against.
    tolerated=0
    for pattern in "${KNOWN_FAILURES[@]}"; do
      if grep -qF "$pattern" "$log"; then
        tolerated=$((tolerated + 1))
      fi
    done
    floor=0
    source="no baseline, tolerating $tolerated known failure(s)"
  fi

  echo "[$batch] Total: $total  OK: $ok  KO: $ko  Crash: $crash" \
       "Warning: $warning  Skip: $skip ($source)"

  if [[ $problems -gt $tolerated ]]; then
    echo "FAIL [$batch]: $problems problem(s) reported, $tolerated tolerated."
    echo "             Failing tests reported:"
    failure_lines "$log" | sed 's/^/               /'
    sed -n '1,/^ *Total: [0-9]*$/p' "$log" | grep -E '^Warn: ' |
      sed 's/^/               /' || true
    return 1
  fi

  if [[ $ok -lt $floor ]]; then
    echo "FAIL [$batch]: only $ok tests passed, below $PASS_FLOOR_PERCENT% of the"
    echo "             $base_ok recorded for the pristine tree. The suite"
    echo "             stopped running a meaningful part of itself."
    return 1
  fi

  return 0
}

for batch in "${BATCHES[@]}"; do
  check_batch "$batch" || result=1
done

if [[ $ran_any -eq 0 ]]; then
  echo "FAIL: no test batch produced a summary, so nothing was actually tested."
  result=1
fi

if [[ $result -ne 0 ]]; then
  # The batch output otherwise only exists in /tmp, which goes away with the
  # container, so surface enough of it to diagnose the failure.
  for batch in "${BATCHES[@]}"; do
    echo "================ tail of ${BATCH_LOG[$batch]} ================"
    tail -40 "${BATCH_LOG[$batch]}" 2>&1 || true
  done
  exit 1
fi

echo "mruby tests passed."

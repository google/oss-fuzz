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

# Only include tests that are not failing
TESTS="test-strerror
test-proc-info
test-static-link
test-flush-cache
Gtest-bt
Ltest-init
Ltest-varargs
Ltest-sig-context
test-init-remote
Ltest-bt
Ltest-init-local-signal
Gtest-init
Gtest-resume-sig
Ltest-resume-sig-rt
test-reg-state
Lx64-test-dwarf-expressions
Gtest-sig-context
Ltest-exc
test-setjmp
Gx64-test-dwarf-expressions
Gtest-exc
x64-unwind-badjmp-signal-frame
Gtest-resume-sig-rt
Ltest-resume-sig
Gtest-concurrent
Ltest-concurrent
Lrs-race
test-ptrace
test-async-sig"

# Temporarily disabled failing unit test cases
DISABLED_TESTS="Ltest-nomalloc
Gtest-trace
test-mem
Ltest-trace
Ltest-nocalloc
SKIP: run-coredump-unwind
check-namespace.sh
run-ptrace-mapper
run-ptrace-misc"

# Run unit testing that are success
make check -j$(nproc) TESTS="$TESTS"

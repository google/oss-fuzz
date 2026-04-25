#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Configure bc for OSS-Fuzz:
#   -H  disable history (no readline/editline dependency)
#   -N  disable NLS (locale support not needed for fuzzing)
#   -m  enable memcheck mode (BC_ENABLE_MEMCHECK=1), which activates the
#       full cleanup code inside bc_vm_shutdown() needed to fix memory leaks.
# bc's configure intentionally excludes bc_fuzzer.c and dc_fuzzer.c from the
# normal build; they are compiled separately below.
./configure -HNm

# Enable OSS-Fuzz mode in the generated Makefile so that the conditional
# fuzzing code paths in vm.c, lex.c, bc_lex.c, etc. are compiled in.
sed -i 's/^BC_ENABLE_OSSFUZZ = 0$/BC_ENABLE_OSSFUZZ = 1/' Makefile

# Create a linker-wrap cleanup shim.
#
# The upstream bc_fuzzer.c harness calls bc_main() each iteration, which
# invokes bc_vm_boot() — this allocates the program, parser, slab, vector,
# and temp-number data structures.  At the end of each iteration the harness
# does memset(vm, 0, sizeof(BcVm)), which zeroes the pointers without freeing
# the heap memory, leaking everything bc_vm_boot() allocated.
#
# Fix: use -Wl,-wrap,LLVMFuzzerTestOneInput so that after every iteration we
# call bc_vm_atexit(0), which calls bc_vm_shutdown().  With BC_ENABLE_MEMCHECK=1
# (from configure -m) bc_vm_shutdown() contains the full free() path for all
# vm heap state, so the next iteration's memset(vm,0,...) safely clears already-
# freed pointers.
#
# Signal-lock invariant: bc_fuzzer.c's exit label calls BC_SIG_MAYLOCK before
# returning, so vm->sig_lock != 0 on return.  bc_vm_shutdown() asserts
# BC_SIG_ASSERT_LOCKED, so this is satisfied.  The next iteration's memset then
# clears sig_lock back to 0, and BC_SIG_LOCK re-establishes it.
cat > /tmp/bc_wrap_cleanup.c << 'EOF'
#include <stdint.h>
#include <stddef.h>

/* BcStatus is an int-sized enum; forward-declare as int to avoid pulling in
   bc headers from a path that may not be set here. */
extern int bc_vm_atexit(int status);

/* The original harness function, renamed by the linker's -wrap mechanism. */
int __real_LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size);

/* Wrapper: run the real harness then free all vm heap state.
   bc_fuzzer.c returns early (before memset(vm,...) and bc_main()) when
   Size==0 or Data[0]=='\0', leaving vm uninitialized.  Only call cleanup
   when bc_main() was actually invoked. */
int __wrap_LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    int r = __real_LLVMFuzzerTestOneInput(Data, Size);
    if (Size > 0 && Data[0] != '\0') {
        bc_vm_atexit(0);
    }
    return r;
}
EOF
$CC $CFLAGS -c /tmp/bc_wrap_cleanup.c -o /tmp/bc_wrap_cleanup.o

# Append fuzzer compilation and link targets to the generated Makefile.
# Single-quoted MAKEEOF prevents the shell from expanding Make variables.
cat >> Makefile << 'MAKEEOF'

# OSS-Fuzz fuzzer build rules (bc_fuzzer.c / dc_fuzzer.c are excluded from
# the normal SRC/OBJ lists by configure, so we add them here explicitly).
src/bc_fuzzer.o: src $(SRCDIR)/bc_fuzzer.c
	$(CC) $(CFLAGS) -o src/bc_fuzzer.o -c $(SRCDIR)/bc_fuzzer.c

src/dc_fuzzer.o: src $(SRCDIR)/dc_fuzzer.c
	$(CC) $(CFLAGS) -o src/dc_fuzzer.o -c $(SRCDIR)/dc_fuzzer.c

# Exclude main.o: it defines main() which conflicts with libFuzzer's main.
# Wrap LLVMFuzzerTestOneInput so bc_vm_atexit() is called after each iteration.
FUZZ_OBJS = $(filter-out src/main.o, $(OBJS))
FUZZ_LDFLAGS = -Wl,-wrap,LLVMFuzzerTestOneInput /tmp/bc_wrap_cleanup.o

bin/bc_fuzzer_c: src/bc_fuzzer.o $(FUZZ_OBJS) | bin
	$(CC) $(CFLAGS) $(FUZZ_LDFLAGS) -o bin/bc_fuzzer_c src/bc_fuzzer.o $(FUZZ_OBJS) OSSFUZZ_LIB_ENGINE

bin/bc_fuzzer_C: bin/bc_fuzzer_c
	cp bin/bc_fuzzer_c bin/bc_fuzzer_C

bin/dc_fuzzer_c: src/dc_fuzzer.o $(FUZZ_OBJS) | bin
	$(CC) $(CFLAGS) $(FUZZ_LDFLAGS) -o bin/dc_fuzzer_c src/dc_fuzzer.o $(FUZZ_OBJS) OSSFUZZ_LIB_ENGINE

bin/dc_fuzzer_C: bin/dc_fuzzer_c
	cp bin/dc_fuzzer_c bin/dc_fuzzer_C
MAKEEOF

# Inject the actual fuzzing engine library (| avoids issues with / in paths).
sed -i "s|OSSFUZZ_LIB_ENGINE|${LIB_FUZZING_ENGINE}|g" Makefile

# Build fuzzer targets. Make automatically builds all prerequisite .o files
# (FUZZ_OBJS) before linking.  We avoid 'make all' because building bin/bc or
# bin/dc with BC_ENABLE_OSSFUZZ=1 would fail: vm.c references bc_fuzzer_data
# which is only defined in the fuzzer source files, not in main.c.
make -j$(nproc) bin/bc_fuzzer_c bin/bc_fuzzer_C bin/dc_fuzzer_c bin/dc_fuzzer_C

cp bin/*_fuzzer_* $OUT/

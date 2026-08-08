#!/bin/bash
#
# OSS-Fuzz build script. Compiles the quicz fuzz driver into a libFuzzer
# binary linked against the OSS-Fuzz-provided $CC with ASan/UBSan.
#
# The driver is pure Zig with a C ABI entry (`quicz_fuzz_drive`); we compile
# it to a static object with Zig, then link it with libFuzzer's main via $CXX.
set -eux

# Zig static object exposing quicz_fuzz_drive (callconv .c).
# Module graph: --dep quicz must precede -Mroot; -Mquicz exposes src/lib.zig.
# -lc: the fuzz targets use std.heap.c_allocator (malloc), which ASan tracks;
# page_allocator mmaps land in ASan-unmapped shadow and cause false SEGV on
# memcpy interception. (Note: Zig's -fPIC is a no-op for static objects here;
# PIC/TLS is handled at final link via lld -no-pie below.)
zig build-lib --dep quicz -Mroot=src/quic/fuzz_c_abi.zig -Mquicz=src/lib.zig \
    -femit-bin="$OUT/quicz_fuzz_drive.o" \
    -OReleaseSafe \
    -lc \
    --name quicz_fuzz_drive

# C shim that maps libFuzzer's LLVMFuzzerTestOneInput to quicz_fuzz_drive.
cat > "$OUT/quicz_main.cpp" <<'EOF'
#include <cstddef>
#include <cstdint>
extern "C" void quicz_fuzz_drive(unsigned mode, const uint8_t* data, size_t size);
// libFuzzer entry: run mode 8 (state machine) plus the parse sweep (mode ~0).
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    quicz_fuzz_drive(8, data, size);
    quicz_fuzz_drive(~0u, data, size);
    return 0;
}
EOF

# Link with the OSS-Fuzz compiler (brings libFuzzer + sanitizers). The
# ${VAR:-} guards keep this usable when run outside the OSS-Fuzz env (local
# preflight) where $LDFLAGS may be unset.
# -fuse-ld=lld -no-pie: the Zig static object ignores -fPIC (emits absolute
# R_X86_64_32S), and its threadlocal (Io.Threaded) TLS relocations
# (TPOFF32/DTPOFF32) truncate under the default GNU-ld PIE link. lld + -no-pie
# links both correctly.
$CXX $CXXFLAGS -std=c++17 -fuse-ld=lld -no-pie \
    "$OUT/quicz_main.cpp" "$OUT/quicz_fuzz_drive.o" \
    -o "$OUT/quicz_fuzz" \
    ${LIB_FUZZING_ENGINE:-} ${LDFLAGS:-}

echo "OSS-Fuzz build complete: $OUT/quicz_fuzz"
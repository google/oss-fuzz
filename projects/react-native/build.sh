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

# ---------------------------------------------------------------------------
# Locate ReactCommon root.
#
# React Native 0.71+ uses a monorepo layout:
#   packages/react-native/ReactCommon/
# Older checkouts (pre-0.71) placed it at the repo root:
#   ReactCommon/
# We detect which layout is present so the script is forward-compatible.
# ---------------------------------------------------------------------------
if [ -d "$SRC/react-native/packages/react-native/ReactCommon" ]; then
    RN_COMMON="$SRC/react-native/packages/react-native/ReactCommon"
else
    RN_COMMON="$SRC/react-native/ReactCommon"
fi

FAST_FLOAT_INCLUDE="$SRC/fast_float/include"
MAPBUF_DIR="${RN_COMMON}/react/renderer/mapbuffer"

# ---------------------------------------------------------------------------
# glog stub  (header-only; replaces the installed libgoogle-glog-dev)
#
# The OSS-Fuzz base-runner image does not include libglog.so.0, so
# dynamically linking it produces a "cannot open shared object" crash at
# fuzzer startup.  Statically linking libglog.a also fails because the
# system package was compiled with libstdc++, but OSS-Fuzz uses libc++.
#
# Solution: shadow the real <glog/logging.h> with a header-only stub that
# compiles all LOG()/CHECK() macros to no-ops or abort().  This works
# because:
#   • MapBuffer.cpp calls LOG(ERROR) only when bufferSize check fails.
#   • Our harness patches that field before construction, so the LOG path
#     is never reached during fuzzing.
#   • CHECK() → abort() preserves crash signal for real violations.
# ---------------------------------------------------------------------------
mkdir -p /src/glog_stub/glog
cat > /src/glog_stub/glog/logging.h <<'GLOGHDR'
#pragma once
#include <cstdlib>   // abort()
// Minimal glog stub for OSS-Fuzz builds.
struct _GlogNullStream {
    template<typename T>
    constexpr _GlogNullStream operator<<(T const&) const noexcept { return {}; }
};
#define LOG(severity)        (_GlogNullStream{})
#define LOG_IF(sev, cond)    if (false) (_GlogNullStream{})
#define DLOG(severity)       (_GlogNullStream{})
#define VLOG(level)          if (false) (_GlogNullStream{})
#define CHECK(cond)          do { if (!(cond)) ::abort(); } while (0)
#define CHECK_EQ(a,b)        CHECK((a)==(b))
#define CHECK_NE(a,b)        CHECK((a)!=(b))
#define CHECK_LT(a,b)        CHECK((a)<(b))
#define CHECK_LE(a,b)        CHECK((a)<=(b))
#define CHECK_GT(a,b)        CHECK((a)>(b))
#define CHECK_GE(a,b)        CHECK((a)>=(b))
#define DCHECK(cond)         ((void)(cond))
#define DCHECK_EQ(a,b)       ((void)(a))
#define GOOGLE_GLOG_DLL_DECL
namespace google {
    inline void InitGoogleLogging(const char*) {}
    inline void ShutdownGoogleLogging() {}
}
GLOGHDR

# ---------------------------------------------------------------------------
# Shared compile flags inherited by every translation unit.
#
# -std=c++20         CSS parser uses concepts and std::ranges (C++20).
# -DNDEBUG           Reflects production build configuration.
# -I/src/glog_stub   Shadow the system glog headers with the stub above.
#                    Must come BEFORE -I${RN_COMMON} or any system paths.
# -I${RN_COMMON}     Provides <react/…>, <jsi/…> include paths.
# ---------------------------------------------------------------------------
EXTRA_CXXFLAGS="\
  -std=c++20 \
  -DNDEBUG \
  -I/src/glog_stub \
  -I${RN_COMMON} \
  -I${FAST_FLOAT_INCLUDE}"

# ---------------------------------------------------------------------------
# fuzz_mapbuffer – MapBuffer binary deserializer
#
# MapBuffer.cpp depends on:
#   • glog  (LOG(ERROR) macro, always linked even though MapBuffer aborts
#             before reaching it in our patched-header case)
#   • react/debug/react_native_assert.h  (no-op in NDEBUG builds, header-only)
#   • MapBufferBuilder  (MapBuffer::getMapBuffer falls back to
#                        MapBufferBuilder::EMPTY() on missing key)
# ---------------------------------------------------------------------------
$CXX $CXXFLAGS $EXTRA_CXXFLAGS \
    -c "${MAPBUF_DIR}/MapBuffer.cpp" \
    -o "$SRC/MapBuffer.o"

$CXX $CXXFLAGS $EXTRA_CXXFLAGS \
    -c "${MAPBUF_DIR}/MapBufferBuilder.cpp" \
    -o "$SRC/MapBufferBuilder.o"

$CXX $CXXFLAGS $EXTRA_CXXFLAGS \
    "$SRC/fuzz_mapbuffer.cpp" \
    "$SRC/MapBuffer.o" \
    "$SRC/MapBufferBuilder.o" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/fuzz_mapbuffer"

# ---------------------------------------------------------------------------
# fuzz_css_tokenizer – CSS tokenizer (CSSTokenizer)
#
# The entire CSS subsystem is header-only (CSSDummy.cpp is an empty compile
# unit that exists solely so the module produces a library artifact under
# the Android CMake build).  No extra source files or libraries are needed.
# ---------------------------------------------------------------------------
$CXX $CXXFLAGS $EXTRA_CXXFLAGS \
    "$SRC/fuzz_css_tokenizer.cpp" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/fuzz_css_tokenizer"

# ---------------------------------------------------------------------------
# fuzz_css_value_parser – CSS value parser (parseCSSProperty<>)
#
# Exercises the full parsing pipeline: CSSTokenizer → CSSSyntaxParser →
# CSSValueParser → typed data-type parsers for Number, Length, Percentage,
# Angle, and Ratio.  All header-only; same dependency profile as above.
# ---------------------------------------------------------------------------
$CXX $CXXFLAGS $EXTRA_CXXFLAGS \
    "$SRC/fuzz_css_value_parser.cpp" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/fuzz_css_value_parser"

# ---------------------------------------------------------------------------
# Seed corpora
#
# Seed corpora dramatically accelerate coverage by giving libFuzzer a set of
# structurally valid starting inputs instead of random bytes.  OSS-Fuzz picks
# them up automatically from $OUT/{fuzzer_name}_seed_corpus.zip.
#
# MapBuffer seeds are hand-crafted binary blobs matching the wire format:
#   Header(8B): [alignment:u16][count:u16][bufferSize:u32]  (all LE)
#   Bucket(12B): [key:u16][type:u16][data:u64]              (all LE, packed)
#   Dynamic area: type-specific framing (strings, nested buffers, lists)
#
# CSS seeds are UTF-8 text strings representative of real style prop values.
# Both CSS fuzzers share the same seed corpus because they accept the same
# input format (raw CSS value strings).
# ---------------------------------------------------------------------------
python3 - <<'PYEOF'
import struct, zipfile, os

OUT = os.environ['OUT']

# ── MapBuffer corpus ────────────────────────────────────────────────────────
# DataType enum: Boolean=0, Int=1, Double=2, String=3, Map=4, Long=5
# Header::HEADER_ALIGNMENT = 0x00FE (stored as uint16_t LE: 0xFE 0x00)
ALIGN = 0x00FE

def header(count, buf_size):
    return struct.pack('<HHI', ALIGN, count, buf_size)

def bucket(key, dtype, data_int64):
    # Bucket: key(u16) + type(u16) + data(u64), #pragma pack(1)
    return struct.pack('<HHQ', key, dtype, data_int64)

seeds_mb = {}

# Seed 1: Minimum valid empty MapBuffer (8 bytes — header only, count=0)
seeds_mb['empty.mapbuf'] = header(0, 8)

# Seed 2: Single Int32 entry  (key=1, type=Int=1, value=42)
# data field is uint64; getIntAtBucket reads first 4 bytes as int32_t
seeds_mb['single_int.mapbuf'] = (
    header(1, 8 + 12) +
    bucket(1, 1, 42)           # data=42, lower 4B → 42 as int32
)

# Seed 3: Single String entry (key=2, type=String=3, value="hello")
# Dynamic area: [4B length LE][UTF-8 bytes]
# data field of bucket = int32_t offset into dynamic area (= 0)
string_bytes = b'hello'
dyn = struct.pack('<I', len(string_bytes)) + string_bytes
seeds_mb['single_string.mapbuf'] = (
    header(1, 8 + 12 + len(dyn)) +
    bucket(2, 3, 0) +          # offset=0 into dynamic area
    dyn
)

# Seed 4: Single Double entry (key=3, type=Double=2, value=3.14)
import struct as st
dbl_bytes = st.pack('<d', 3.14)
dbl_int64 = st.unpack('<Q', dbl_bytes)[0]
seeds_mb['single_double.mapbuf'] = (
    header(1, 8 + 12) +
    bucket(3, 2, dbl_int64)
)

# Seed 5: Nested Map entry (key=1, type=Map=4)
# Inner buffer = empty MapBuffer (8 bytes)
# Dynamic area: [4B inner_len LE][inner bytes]
inner = header(0, 8)                    # empty MapBuffer as nested child
dyn_map = struct.pack('<I', len(inner)) + inner
seeds_mb['nested_map.mapbuf'] = (
    header(1, 8 + 12 + len(dyn_map)) +
    bucket(1, 4, 0) +           # type=Map, offset=0
    dyn_map
)

# Seed 6: Two-bucket MapBuffer (Int + String); exercises binary search
string2 = b'world'
dyn2 = struct.pack('<I', len(string2)) + string2
seeds_mb['two_buckets.mapbuf'] = (
    header(2, 8 + 12*2 + len(dyn2)) +
    bucket(0x0010, 1, 7) +      # key=16, Int=7
    bucket(0x0020, 3, 0) +      # key=32, String, offset=0
    dyn2
)

with zipfile.ZipFile(OUT + '/fuzz_mapbuffer_seed_corpus.zip', 'w',
                     compression=zipfile.ZIP_STORED) as z:
    for name, data in seeds_mb.items():
        z.writestr(name, data)

# ── CSS corpus (shared by tokenizer + value parser fuzzers) ────────────────
seeds_css = {
    # <number> values
    'num_integer.css':    b'42',
    'num_float.css':      b'3.14',
    'num_negative.css':   b'-0.5',
    'num_sci.css':        b'1.5e2',
    # <length> values
    'len_px.css':         b'16px',
    'len_rem.css':        b'1.5rem',
    'len_vw.css':         b'100vw',
    'len_em.css':         b'0.875em',
    # <percentage> values
    'pct_50.css':         b'50%',
    'pct_100.css':        b'100%',
    'pct_frac.css':       b'33.333%',
    # <angle> values
    'angle_deg.css':      b'90deg',
    'angle_rad.css':      b'1.5708rad',
    'angle_turn.css':     b'0.25turn',
    'angle_grad.css':     b'100grad',
    # <ratio> values
    'ratio_16_9.css':     b'16 / 9',
    'ratio_4_3.css':      b'4/3',
    # CSS-wide keywords (always attempted first by parseCSSProperty)
    'kw_initial.css':     b'initial',
    'kw_inherit.css':     b'inherit',
    'kw_unset.css':       b'unset',
    # Edge cases
    'edge_nul.css':       b'16\x00px',   # embedded NUL (EndOfFile sentinel)
    'edge_highbyte.css':  b'\xc3\xa9m',  # UTF-8 high-byte in ident
    'edge_hash.css':      b'#ff0000',    # hash token
    'edge_func.css':      b'rgba(',      # function token, unclosed
    'edge_empty.css':     b'',
}

for fuzzer in ('fuzz_css_tokenizer', 'fuzz_css_value_parser'):
    with zipfile.ZipFile(OUT + f'/{fuzzer}_seed_corpus.zip', 'w',
                         compression=zipfile.ZIP_STORED) as z:
        for name, data in seeds_css.items():
            z.writestr(name, data)
PYEOF

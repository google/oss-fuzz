#!/bin/bash -eu
# Copyright 2023 Google LLC
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

export USE_BAZEL_VERSION=7.4.0
# The repository is WORKSPACE-only; keep Bazel 7's default Bzlmod from
# resolving modules the build does not declare.
echo "common --noenable_bzlmod" >> .bazelrc

bazel_build_fuzz_tests

# Seeds: wrap the ADTS and DAB+ streams in tests/data into fuzz_decode's
# input format (len1, len2, flags, NeAACDecConfiguration, part1..3).
python3 - "$OUT" tests/data <<'PY'
import os, struct, sys, zipfile

out, data = sys.argv[1], sys.argv[2]

# NeAACDecConfiguration on LP64: objtype, pad, unsigned long rate,
# outputFormat, downMatrix, useOldADTSFormat, dontUpSampleImplicitSBR, pad.
config = struct.pack("<B7xQBBBB4x", 2, 44100, 1, 0, 0, 0)

def seed(part1, part2, part3, flags):
    return (struct.pack("<HHB", len(part1), len(part2), flags) + config +
            part1 + part2 + part3)

def adts_frame_len(d, pos):
    if pos + 7 <= len(d) and d[pos] == 0xFF and (d[pos + 1] & 0xF6) == 0xF0:
        return ((d[pos + 3] & 3) << 11) | (d[pos + 4] << 3) | (d[pos + 5] >> 5)
    return 0

seeds = {}
for name in sorted(os.listdir(data)):
    path = os.path.join(data, name)
    if not name.endswith(".aac"):
        continue
    d = open(path, "rb").read()[:60000]
    n = adts_frame_len(d, 0) or len(d) // 2
    head, frame, rest = d[:min(len(d), 4096)], d[:n], d[n:]
    seeds[name + ".init"] = seed(head, frame, rest, 0)
    # NeAACDecDecode2 into a 16 KiB buffer, with a seek reset in between.
    seeds[name + ".decode2"] = seed(head, frame, rest, (3 << 3) | 4)

dab = os.path.join(data, "dab")
for name in sorted(os.listdir(dab)) if os.path.isdir(dab) else []:
    d = open(os.path.join(dab, name), "rb").read()
    asc_len = struct.unpack_from("<I", d, 0)[0]
    asc, pos, frames = d[4:4 + asc_len], 4 + asc_len, []
    while pos + 4 <= len(d) and len(frames) < 2:
        flen = struct.unpack_from("<I", d, pos)[0]
        frames.append(d[pos + 4:pos + 4 + flen])
        pos += 4 + flen
    if len(frames) == 2:
        seeds[name + ".init2"] = seed(asc, frames[0], frames[1], 1)

with zipfile.ZipFile(os.path.join(out, "fuzz_decode_seed_corpus.zip"), "w") as z:
    for k, v in seeds.items():
        z.writestr(k, v)
print("fuzz_decode seeds:", len(seeds))
PY

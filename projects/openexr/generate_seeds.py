#!/usr/bin/env python3
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
"""Structured seed generator for the OpenEXR file-reading fuzzers.

OpenEXR's production corpus already exercises every classic compression codec
(ZIP/PIZ/PXR24/B44/RLE/DWA are all 82-98% covered), but the newer **Zstd**
compression (EXR_COMPRESSION_ZSTD) is essentially dark: in the production
coverage report ``internal_zstd_delta.c`` is 0%, ``internal_zstd_shuffle.c``
23% and ``internal_zstd.c`` 43% -- no corpus input is a Zstd-compressed EXR, so
the Zstd decode path (zstd decompress -> un-shuffle -> delta-decode) is never
reached by mutation (random bytes never form a valid EXR container, let alone a
valid Zstd chunk stream).

This script writes a handful of small, structurally valid Zstd-compressed EXR
files using OpenEXR's own Python bindings (the canonical writer), so the file
readers have a real Zstd starting point to mutate from.  The decoder -- not this
generator -- is the attack surface: the Zstd chunk parser and the shuffle/delta
post-filters operate on attacker-controlled compressed scanline data.

Channel type matters for which decode paths are reached:
  * HALF  (2-byte) channels -> shuffle (2-byte elems) + delta_decode_row_u16
  * UINT  (4-byte) channels -> shuffle (4-byte elems) + delta_decode_row_u32
  * FLOAT channels          -> the no-delta float path

Seeds are deterministic (fixed gradients) and purely additive to the existing
corpus, so they cannot cause coverage digression.

Usage: generate_seeds.py <output-dir>
"""
import os
import sys

import numpy as np
import OpenEXR


def _channels(width, height, dtype, names):
    chans = {}
    yy, xx = np.meshgrid(np.arange(height), np.arange(width), indexing='ij')
    for i, c in enumerate(names):
        # A smooth-ish gradient gives the shuffle/delta filters real,
        # non-trivial deltas to encode (and the decoder to reverse).
        chans[c] = ((xx * 3 + yy * 7 + i * 11) % 251).astype(dtype)
    return chans


def _write_zstd_exr(out_dir, name, width, height, dtype, channel_names):
    header = {
        'compression': OpenEXR.ZSTD_COMPRESSION,
        'type': OpenEXR.scanlineimage,
    }
    chans = _channels(width, height, dtype, channel_names)
    exr = OpenEXR.File(header, chans)
    path = os.path.join(out_dir, name)
    exr.write(path)
    print('  wrote %-30s %7d bytes' % (name, os.path.getsize(path)))


def gen_openexr(out_dir):
    # HALF channels -> 2-byte shuffle + delta_decode_row_u16.
    _write_zstd_exr(out_dir, 'zstd_half_rgb_32x32.exr', 32, 32, np.float16,
                    ['R', 'G', 'B'])
    _write_zstd_exr(out_dir, 'zstd_half_rgba_17x9.exr', 17, 9, np.float16,
                    ['R', 'G', 'B', 'A'])
    _write_zstd_exr(out_dir, 'zstd_half_r_64x8.exr', 64, 8, np.float16, ['R'])

    # UINT channels -> 4-byte shuffle + delta_decode_row_u32.
    _write_zstd_exr(out_dir, 'zstd_uint_rg_24x16.exr', 24, 16, np.uint32,
                    ['R', 'G'])

    # FLOAT channels -> the non-delta float path.
    _write_zstd_exr(out_dir, 'zstd_float_rgb_16x16.exr', 16, 16, np.float32,
                    ['R', 'G', 'B'])


def main():
    if len(sys.argv) < 2:
        sys.stderr.write('usage: %s <output-dir>\n' % sys.argv[0])
        return 1
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    print('Generating OpenEXR Zstd seeds:')
    gen_openexr(out_dir)
    return 0


if __name__ == '__main__':
    sys.exit(main())

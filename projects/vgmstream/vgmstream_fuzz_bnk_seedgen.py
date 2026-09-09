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
"""
vgmstream_bnk_seedgen.py -- seed generator for the vgmstream
PS BNK demuxer fuzz campaign.

Hand-crafts minimal valid BNK files for each sblk version documented in
bnk_sony.c.  Goal is NOT to produce real game audio — only enough header
to get past parse_bnk()'s sniff and into the version-specific table parser
where the interesting bugs live.

File layout (verified against bnk_sony.c:1320-1359):

  off  size  field
  0x00 4     container version (1 or 3)        -- 1=v1, 3=v3
  0x04 4     sections count (2 or 3)
  0x08 4     sblk_offset (≤ 0x20)
  0x0c 4     sblk_size (unused)
  0x10 4     data_offset
  0x14 4     data_size
  0x18 4     zlsd_offset (only if sections>=3)
  0x1c 4     zlsd_size   (only if sections>=3)

SBlk part at sblk_offset (typically 0x20):

  v1:  magic "SBv2", sblk_version=0x02 at +0x04
  v3:  magic "SBlk", sblk_version (0x03..0x23) at +0x04

Then version-specific tables follow.  See bnk_sony.c:process_tables() for
field offsets per version.

Output:
    snippingtool_corpus_jxr/  (no, that's the other project — see below)
    vgmstream_bnk_seeds/

SOP: every file fresh, prefixed vgmstream_*.  No reuse.
"""

import os
import struct
import sys

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "vgmstream_bnk_seeds"
os.makedirs(OUT_DIR, exist_ok=True)

def le32(v): return struct.pack("<I", v & 0xFFFFFFFF)
def le16(v): return struct.pack("<H", v & 0xFFFF)
def be32(v): return struct.pack(">I", v & 0xFFFFFFFF)
def be16(v): return struct.pack(">H", v & 0xFFFF)

def write_seed(name, data, size=512):
    """Pad/truncate to `size` bytes and write."""
    if len(data) > size:
        size = len(data) + 64
    pad = size - len(data)
    if pad > 0:
        data = data + bytes(pad)
    path = os.path.join(OUT_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {len(data):4d}B  {name}")

def make_file_header(container_ver, sections, sblk_offset=0x20,
                     data_offset=0x200, data_size=0x100,
                     zlsd_offset=0x300, zlsd_size=0x10):
    """Build the 0x00-0x1f file header."""
    h  = le32(container_ver)        # 0x00 container version
    h += le32(sections)              # 0x04 sections
    h += le32(sblk_offset)           # 0x08 sblk_offset
    h += le32(0x100)                 # 0x0c sblk_size (unused)
    h += le32(data_offset)           # 0x10 data_offset
    h += le32(data_size)             # 0x14 data_size
    if sections >= 3:
        h += le32(zlsd_offset)       # 0x18 zlsd_offset
        h += le32(zlsd_size)         # 0x1c zlsd_size
    else:
        h += b"\x00" * 8             # pad
    return h

def make_v1_seed():
    """Container version 1 → SBv2 magic, sblk_version=0x02"""
    fhdr = make_file_header(container_ver=1, sections=2)
    sblk  = b"SBv2"                  # magic at sblk_offset+0x00
    sblk += le32(0x02)               # sblk_version at +0x04
    # v1/v2 process_tables uses sblk_offset+0x14..0x1a for entry counts,
    # then +0x1c..0x20 for table offsets
    sblk += b"\x00" * 0x0c           # 0x08..0x13 padding
    sblk += le16(2)                  # 0x14 sounds_entries (case 0x02)
    sblk += le16(2)                  # 0x16 grains_entries
    sblk += le16(0)                  # 0x18 (unused/waves)
    sblk += le16(1)                  # 0x1a stream_entries
    sblk += le32(0x40)               # 0x1c table1_offset (rel to sblk)
    sblk += le32(0x60)               # 0x20 table2_offset (rel to sblk)
    sblk += le32(0x80)               # 0x24 table3_offset
    return fhdr + sblk

def make_v3_seed(sblk_version, table_layout="early"):
    """
    Container version 3 → SBlk magic, sblk_version varies.

    table_layout:
      "early"  → versions 0x03..0x09  (counts at +0x16/+0x18/+0x1a, offsets at +0x1c..)
      "mid"    → versions 0x0c..0x10  (offsets at +0x18..+0x30, counts at +0x38..)
      "late"   → versions 0x1a/0x1c/0x23 (different layout entirely)
    """
    fhdr = make_file_header(container_ver=3, sections=2)
    sblk  = b"SBlk"                  # magic
    sblk += le32(sblk_version)       # sblk_version

    if table_layout == "early":
        sblk += b"\x00" * 0x0e       # pad to 0x16
        sblk += le16(2)              # 0x16 sounds_entries
        sblk += le16(2)              # 0x18 grains_entries
        sblk += le16(1)              # 0x1a stream_entries
        sblk += le32(0x40)           # 0x1c table1_offset
        sblk += le32(0x60)           # 0x20 table2_offset
        sblk += le32(0x80)           # 0x24 (vag addr)
        sblk += le32(0x90)           # 0x28 (data size)
        sblk += le32(0xa0)           # 0x2c (ram size)
        sblk += le32(0xb0)           # 0x30 (next block offset)
        sblk += le32(0xc0)           # 0x34 table3_offset
        sblk += le32(0xd0)           # 0x38 table4_offset

    elif table_layout == "mid":
        sblk += b"\x00" * 0x10       # pad to 0x18
        sblk += le32(0x40)           # 0x18 table1_offset
        sblk += le32(0x60)           # 0x1c table2_offset
        sblk += b"\x00" * 0x0c       # pad
        sblk += le32(0x80)           # 0x2c table3_offset
        sblk += le32(0xa0)           # 0x30 table4_offset
        sblk += b"\x00" * 0x04       # pad
        sblk += le16(2)              # 0x38 sounds_entries
        sblk += le16(2)              # 0x3a grains_entries
        sblk += le16(1)              # 0x3c stream_entries

    elif table_layout == "late":
        # versions 0x1a/0x1c/0x23 — bank_name + tables_offset structures
        sblk += b"\x00" * 0x14       # pad
        # bank_name area (0x1c or 0x20)
        sblk += b"vgmstream_bnk\x00\x00\x00"  # bank name
        sblk += b"\x00" * 0x100       # name continues
        # tables_offset is at sblk+0x120 or sblk+0x128
        # counts_offset = tables_offset + 0x98 or +0xb0
        sblk += le32(0x40)            # tables_offset+0x00
        sblk += le32(0x60)            # +0x04
        sblk += le32(0x80)            # +0x08 table3_offset
        sblk += b"\x00" * 0x100        # pad to counts area
        sblk += le16(2)               # sounds
        sblk += le16(2)               # grains
        sblk += le16(0)               # waves
        sblk += le16(1)               # stream_entries

    return fhdr + sblk

def make_zlsd_seed():
    """Sections=3 → triggers ZLSD parsing path"""
    fhdr = make_file_header(container_ver=3, sections=3,
                            zlsd_offset=0x300, zlsd_size=0x40)
    sblk  = b"SBlk" + le32(0x09) + b"\x00" * 0xf8
    return fhdr + sblk

def make_be_seed():
    """Big-endian variant — guess_endian32 picks BE if v=01000000"""
    h  = be32(1)                 # version 1 in BE
    h += be32(2)                 # sections
    h += be32(0x20)              # sblk_offset
    h += be32(0x100)             # sblk_size
    h += be32(0x200)             # data_offset
    h += be32(0x100)             # data_size
    h += b"\x00" * 8
    sblk  = b"2vBS"              # SBv2 reversed (BE)
    sblk += be32(0x02)
    return h + sblk

# ---------- generate ----------
print(f"writing seeds to {OUT_DIR}/")

write_seed("vgmstream_bnk_seed_v1.bin", make_v1_seed())
write_seed("vgmstream_bnk_seed_v3_03.bin", make_v3_seed(0x03, "early"))
write_seed("vgmstream_bnk_seed_v3_04.bin", make_v3_seed(0x04, "early"))
write_seed("vgmstream_bnk_seed_v3_05.bin", make_v3_seed(0x05, "early"))
write_seed("vgmstream_bnk_seed_v3_08.bin", make_v3_seed(0x08, "early"))
write_seed("vgmstream_bnk_seed_v3_09.bin", make_v3_seed(0x09, "early"))
write_seed("vgmstream_bnk_seed_v3_0c.bin", make_v3_seed(0x0c, "mid"))
write_seed("vgmstream_bnk_seed_v3_0d.bin", make_v3_seed(0x0d, "mid"))
write_seed("vgmstream_bnk_seed_v3_0e.bin", make_v3_seed(0x0e, "mid"))
write_seed("vgmstream_bnk_seed_v3_0f.bin", make_v3_seed(0x0f, "mid"))
write_seed("vgmstream_bnk_seed_v3_10.bin", make_v3_seed(0x10, "mid"))
write_seed("vgmstream_bnk_seed_v3_1a.bin", make_v3_seed(0x1a, "late"), size=1024)
write_seed("vgmstream_bnk_seed_v3_1c.bin", make_v3_seed(0x1c, "late"), size=1024)
write_seed("vgmstream_bnk_seed_v3_23.bin", make_v3_seed(0x23, "late"), size=1024)
write_seed("vgmstream_bnk_seed_zlsd.bin", make_zlsd_seed(), size=1024)
write_seed("vgmstream_bnk_seed_be.bin",   make_be_seed())

# Edge case: maximum entry counts (likely to trigger int overflow)
def make_overflow_seed():
    fhdr = make_file_header(container_ver=3, sections=2)
    sblk  = b"SBlk" + le32(0x05)
    sblk += b"\x00" * 0x0e
    sblk += le16(0xFFFF)         # max sounds_entries
    sblk += le16(0xFFFF)         # max grains_entries
    sblk += le16(0xFFFF)         # max stream_entries
    sblk += le32(0xFFFFFFFF)     # huge table1_offset
    sblk += le32(0xFFFFFFFF)     # huge table2_offset
    return fhdr + sblk

def make_underflow_seed():
    fhdr = make_file_header(container_ver=3, sections=2,
                            sblk_offset=0x20, data_offset=0,
                            data_size=0xFFFFFFFF)
    sblk  = b"SBlk" + le32(0x09)
    sblk += b"\x00" * 0x0e
    sblk += le16(0)              # zero counts
    sblk += le16(0)
    sblk += le16(0)
    sblk += le32(0)              # zero offsets
    return fhdr + sblk

write_seed("vgmstream_bnk_seed_overflow.bin", make_overflow_seed())
write_seed("vgmstream_bnk_seed_underflow.bin", make_underflow_seed())

print(f"\ntotal seeds: {len(os.listdir(OUT_DIR))}")

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
# Generates MPEG Program Stream (.vob / .mpg) seed files for the
# vlc-demux-dec-libfuzzer-ps fuzzer target.
#
# The upstream vlc-fuzz-corpus seeds/ps/dvd_subtitle.vob has the correct PS+PES
# wrapping but a malformed SPU header (i_spu_size=0x2000 / 8192 bytes, but only
# ~40 bytes of payload). The spudec packetizer (modules/codec/spudec/spudec.c
# Reassemble) holds the block waiting for 8192 bytes that never arrive, so
# modules/codec/spudec/parse.c (the actual SPU command/RLE parser) is never
# invoked and stays at 0% line coverage.
#
# This script writes a structurally complete DVD SPU PES whose i_spu_size
# matches the actual payload, so the assembled buffer is delivered to
# ParsePacket() / ParseControlSeq() / ParseRLE() in parse.c.

import os
import struct
import sys


# ---------- PS pack + PES helpers ----------

def make_ps_pack_header(scr_90khz: int = 0, mux_rate: int = 0x1869F) -> bytes:
    """MPEG-2 PS pack header (14 bytes including the 0x000001BA start code).

    Layout (after the 4-byte start code):
      6 bytes  SCR_base(33) + SCR_ext(9) packed with marker bits
      3 bytes  program_mux_rate(22) + 2 reserved bits
      1 byte   reserved(5) + pack_stuffing_length(3)
    """
    base = scr_90khz & ((1 << 33) - 1)
    ext = 0
    b = bytes([
        # 01 + base[32:30] + marker + base[29:15][14:13]
        0x40 | ((base >> 27) & 0x38) | 0x04 | ((base >> 28) & 0x03),
        (base >> 20) & 0xFF,
        ((base >> 12) & 0xF8) | 0x04 | ((base >> 13) & 0x03),
        (base >> 5) & 0xFF,
        ((base << 3) & 0xF8) | 0x04 | ((ext >> 7) & 0x03),
        ((ext << 1) & 0xFE) | 0x01,
        (mux_rate >> 14) & 0xFF,
        (mux_rate >> 6) & 0xFF,
        ((mux_rate << 2) & 0xFC) | 0x03,
        0xF8,                                   # reserved + stuffing_length=0
    ])
    return bytes([0x00, 0x00, 0x01, 0xBA]) + b


def make_pes(stream_id: int, payload: bytes, pts_90khz: int = 9000) -> bytes:
    """PES packet (0x000001 + stream_id + length + optional header + payload)."""
    p = pts_90khz
    pts_bytes = bytes([
        0x21 | ((p >> 29) & 0x0E),
        (p >> 22) & 0xFF,
        0x01 | ((p >> 14) & 0xFE),
        (p >> 7) & 0xFF,
        0x01 | ((p << 1) & 0xFE),
    ])
    optional = bytes([0x80, 0x80, len(pts_bytes)]) + pts_bytes  # PTS-only flags
    pes_length = len(optional) + len(payload)
    assert pes_length < 65536
    return bytes([0x00, 0x00, 0x01, stream_id]) \
        + struct.pack('>H', pes_length) \
        + optional + payload


# ---------- DVD SPU body ----------

def make_dvd_spu() -> bytes:
    """Build a minimal but structurally complete DVD subtitle SPU body.

    Format (Sam Hocevar's DVD subtitle spec, modules/codec/spudec/parse.c):
      offset 0: i_spu_size               (uint16 BE)  total SPU size
      offset 2: i_control_offset         (uint16 BE)  = 4 + i_rle_size
      offset 4: RLE pixel data           (i_rle_size bytes)
      offset i_control_offset: control sequences:
        date(2) | next_offset(2) | commands... | 0xFF
      Commands:
        0x00 force_display
        0x01 start_display
        0x02 stop_display
        0x03 palette        (2 bytes — four 4-bit indices)
        0x04 alpha          (2 bytes — four 4-bit values)
        0x05 coordinates    (6 bytes — x_start/x_end/y_start/y_end as 12-bit)
        0x06 pixel offsets  (4 bytes — top_field_offset, bottom_field_offset)
        0x07 PXCTLI table   (length(2) + table data)
        0xFF end-of-sequence
    """
    # 8 bytes of RLE that decode as a single transparent run terminated by
    # end-of-line (0x0000) per the 4-bit/8-bit RLE rules in ParseRLE().
    rle = bytes([0x40, 0x00, 0x00, 0x00,            # top field
                 0x40, 0x00, 0x00, 0x00])           # bottom field
    rle_size = len(rle)
    control_offset = 4 + rle_size

    # First control sequence: install palette/alpha/coords/offsets + start_display.
    seq1_off = control_offset
    seq2_off = seq1_off + (4                                   # date+next
                           + 1 + 2                             # cmd 03 palette
                           + 1 + 2                             # cmd 04 alpha
                           + 1 + 6                             # cmd 05 coords
                           + 1 + 4                             # cmd 06 offsets
                           + 1                                 # cmd 01 start
                           + 1)                                # 0xFF terminator
    seq1 = struct.pack('>HH', 0, seq2_off)                     # date=0, next=seq2
    seq1 += bytes([0x03, 0x32, 0x10])                          # palette idx 3,2,1,0
    seq1 += bytes([0x04, 0x0F, 0x00])                          # alpha for indices
    seq1 += bytes([0x05, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10])  # x:0..0x100 y:0..0x100
    seq1 += bytes([0x06]) + struct.pack('>HH', 4, 4 + rle_size // 2)  # field offsets
    seq1 += bytes([0x01])                                      # start display
    seq1 += bytes([0xFF])                                      # end

    # Second control sequence (1 second later): stop display, terminator,
    # next_offset == self -> last sequence in the list.
    seq2 = struct.pack('>HH', 100, seq2_off)                   # date=1.10s, next=self
    seq2 += bytes([0x02])                                      # stop display
    seq2 += bytes([0xFF])                                      # end

    body = rle + seq1 + seq2
    spu_size = 4 + len(body)
    assert spu_size <= 0xFFFF
    return struct.pack('>HH', spu_size, control_offset) + body


# ---------- Seed assembly ----------

SUB_STREAM_ID_DVD_SPU0 = 0x20         # DVD subpicture stream #0


def seed_dvd_subtitle() -> bytes:
    """PS stream carrying a complete DVD SPU PES.

    The PS demuxer's Open() probes 3 PS_PACKET_PROBE packets before accepting
    the stream (modules/demux/mpeg/ps.c:149,187), so we emit pack/PES/pack/
    pack-end to satisfy the probe even when the SPU PES alone would suffice.
    """
    spu = make_dvd_spu()
    pes_payload = bytes([SUB_STREAM_ID_DVD_SPU0]) + spu
    spu_pes = make_pes(0xBD, pes_payload, pts_90khz=9000)
    # A tiny padding-stream PES (stream_id=0xBE) to give the probe loop
    # a recognisable third start code.
    padding_pes = bytes([0x00, 0x00, 0x01, 0xBE]) + struct.pack('>H', 8) + bytes([0xFF] * 8)
    return (make_ps_pack_header(scr_90khz=0)
            + spu_pes
            + make_ps_pack_header(scr_90khz=4500)
            + padding_pes
            + bytes([0x00, 0x00, 0x01, 0xB9]))   # MPEG-PS end-stream marker


SEEDS = {
    'dvd_subtitle.vob': seed_dvd_subtitle,
}


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <output_directory>', file=sys.stderr)
        sys.exit(1)
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    for name, gen in SEEDS.items():
        data = gen()
        with open(os.path.join(outdir, name), 'wb') as f:
            f.write(data)
        print(f'  {name}: {len(data)} bytes')


if __name__ == '__main__':
    main()

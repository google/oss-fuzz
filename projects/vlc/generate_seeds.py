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
# Generates seed corpora and libFuzzer dictionaries for the VLC
# vlc-demux-dec-libfuzzer-* fuzz targets:
#
#   seeds/ts/*.ts             — minimal but structurally valid MPEG-TS streams
#                               (PAT + PMT + PES + ATSC PSIP variants) targeting
#                               modules/demux/mpeg/*.
#   seeds/ps/*.vob            — MPEG Program Stream carrying a structurally
#                               complete DVD SPU PES so spudec/parse.c runs.
#   seeds/heif/*.{heic,avif}  — ftyp + meta(iinf/iloc/iprp) + mdat trees
#                               targeting modules/demux/mp4/heif.c.
#   seeds/rawdv/*.dv          — minimal NTSC / PAL DV frames.
#   seeds/vc1/*.vc1           — VC-1 start-code-prefixed elementary streams.
#   seeds/cdg/*.cdg           — CDG command frames exercising decoder branches.
#   seeds/dmxmus/*.mus           — DOOM-style .MUS music with event variants.
#   dictionaries/{heif,rawdv,vc1,cdg,mus}.dict
#
# Usage:
#     generate_seeds.py <fuzz-corpus-root>

import os
import re
import struct
import sys


# ──────────────────────────────────────────────────
#  TS seed generation (modules/demux/mpeg/*)
# ──────────────────────────────────────────────────
#
# The existing vlc-fuzz-corpus TS seeds are null-packet-only files (PID=0x1FFF
# filled with 0xFF), which means the TS demuxer never reaches PAT/PMT parsing,
# PES demuxing, or any of the stream-specific processing in ts_psi.c, ts_pes.c,
# ts_pid.c, ts_streams.c, ts_decoders.c, ts_scte.c, ts_arib.c, ts_si.c etc.
# Replacing them with seeds that contain PAT + PMT + PES packets dramatically
# increases reachable code in modules/demux/mpeg/*.
#
# Each generated file is exactly N * 188 bytes (valid TS packet boundaries).

def crc32_mpeg(data: bytes) -> int:
    """CRC-32 using the MPEG-2 polynomial 0x04C11DB7 (ISO 13818-1 Annex B)."""
    crc = 0xFFFFFFFF
    for byte in data:
        for _ in range(8):
            if ((crc >> 31) ^ (byte >> 7)) & 1:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
            byte = (byte << 1) & 0xFF
    return crc


def make_ts_packet(pid: int, payload: bytes, pusi: bool = False, cc: int = 0,
                   pcr_90khz: int = None) -> bytes:
    """Assemble a 188-byte TS packet.

    If ``pcr_90khz`` is given, an adaptation field with the PCR flag is added.
    Without PCR delivery, the TS demuxer holds blocks in its prepcr queue and
    never forwards them to decoders, masking the coverage of subtitle/audio
    decoders that depend on the PES path (e.g. modules/codec/dvbsub.c).
    """
    assert 0 <= pid <= 0x1FFF
    b1 = (0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F)
    b2 = pid & 0xFF
    if pcr_90khz is None:
        b3 = 0x10 | (cc & 0x0F)      # adaptation_field_control=0b01 (payload only)
        header = bytes([0x47, b1, b2, b3])
        stuffing = 184 - len(payload)
        assert stuffing >= 0, f"Payload {len(payload)} bytes exceeds 184"
        return header + payload + bytes([0xFF] * stuffing)
    # adaptation_field_control=0b11 (AF + payload)
    b3 = 0x30 | (cc & 0x0F)
    base = pcr_90khz & ((1 << 33) - 1)
    ext = 0
    pcr_bytes = bytes([
        (base >> 25) & 0xFF,
        (base >> 17) & 0xFF,
        (base >> 9)  & 0xFF,
        (base >> 1)  & 0xFF,
        ((base & 0x1) << 7) | 0x7E | ((ext >> 8) & 0x01),
        ext & 0xFF,
    ])
    af_flags = 0x10               # PCR_flag
    af_data = bytes([af_flags]) + pcr_bytes      # 7 bytes
    af_length = len(af_data)                      # 7
    af = bytes([af_length]) + af_data             # 8 bytes total (length byte + 7)
    header = bytes([0x47, b1, b2, b3])
    space = 188 - len(header) - len(af)
    assert len(payload) <= space, \
        f"Payload {len(payload)} bytes exceeds {space} after PCR AF"
    stuffing = space - len(payload)
    return header + af + payload + bytes([0xFF] * stuffing)


def psi_section(table_id: int, tid_ext: int, body: bytes) -> bytes:
    """Wrap body bytes in a PSI section with header + CRC-32."""
    inner = struct.pack('>H', tid_ext) + bytes([0xC1, 0x00, 0x00]) + body
    section_length = len(inner) + 4  # +4 for CRC
    hdr = bytes([table_id]) + struct.pack('>H', 0xB000 | section_length)
    full = hdr + inner
    return full + struct.pack('>I', crc32_mpeg(full))


_PSI_CC_STATE = {}


def psi_packet(section: bytes, pid: int) -> bytes:
    """Wrap a PSI section in a single TS packet (pointer_field = 0x00).
       Continuity counters are tracked per-PID in a module-level dict so
       that successive PSI packets on the same PID present a valid CC
       sequence — dvbpsi otherwise reports "TS discontinuity" and drops
       sections (the cause of seed_atsc_psip's atsc_a65.c coverage being
       zero before this fix)."""
    payload = bytes([0x00]) + section   # pointer_field = 0
    assert len(payload) <= 184, "Section too large for one TS packet"
    cc = _PSI_CC_STATE.get(pid, 0)
    _PSI_CC_STATE[pid] = (cc + 1) & 0x0F
    return make_ts_packet(pid, payload, pusi=True, cc=cc)


def reset_psi_cc():
    """Reset the per-PID CC counter — call between independent seed
       generators so each seed file starts with CC=0."""
    _PSI_CC_STATE.clear()
    _PES_CC_STATE.clear()


def make_pat(programs: list) -> bytes:
    """Build a PAT section.  programs = [(program_number, pmt_pid), ...]"""
    body = b''
    for prog_num, pmt_pid in programs:
        body += struct.pack('>HH', prog_num, 0xE000 | (pmt_pid & 0x1FFF))
    return psi_section(0x00, 0x0001, body)


def make_pmt(program_num: int, pcr_pid: int, streams: list) -> bytes:
    """Build a PMT section.  streams = [(stream_type, es_pid, descriptors), ...]"""
    body = struct.pack('>H', 0xE000 | pcr_pid) + struct.pack('>H', 0xF000)
    for stype, es_pid, descs in streams:
        body += bytes([stype])
        body += struct.pack('>H', 0xE000 | es_pid)
        body += struct.pack('>H', 0xF000 | len(descs))
        body += descs
    return psi_section(0x02, program_num, body)


def make_sdt(tsid: int, orig_net: int, services: dict) -> bytes:
    """Build an SDT (Service Description Table, table_id=0x42).
       services = {service_id: (service_name, service_type)}
    """
    body = struct.pack('>H', orig_net) + b'\xFF'
    for svc_id, (name, svc_type) in services.items():
        svc_name_bytes = name.encode('utf-8')
        desc = bytes([
            0x48,
            3 + len(svc_name_bytes),
            svc_type,
            0x00,
            len(svc_name_bytes),
        ]) + svc_name_bytes
        body += struct.pack('>H', svc_id)
        body += struct.pack('>H', 0x8000 | len(desc))
        body += desc
    section_length = 2 + 1 + 1 + 1 + len(body) + 4
    hdr = bytes([0x42]) + struct.pack('>H', 0xB000 | section_length)
    inner = struct.pack('>H', tsid) + bytes([0xC1, 0x00, 0x00]) + body
    full = hdr + inner
    return full + struct.pack('>I', crc32_mpeg(full))


def make_ts_pes(stream_id: int, payload: bytes, pts_90khz: int = 0) -> bytes:
    """Build a PES packet with optional PTS (TS-style; length field 0 when oversized)."""
    if pts_90khz is not None:
        p = pts_90khz
        pts = bytes([
            0x21 | ((p >> 29) & 0x0E),
            (p >> 22) & 0xFF,
            0x01 | ((p >> 14) & 0xFE),
            (p >> 7) & 0xFF,
            0x01 | ((p << 1) & 0xFE),
        ])
        flag2 = 0x80   # PTS_DTS_flags = 10 (PTS only)
        header_data = pts
    else:
        flag2 = 0x00
        header_data = b''

    header_data_len = len(header_data)
    optional = bytes([0x80, flag2, header_data_len]) + header_data
    pes_data = bytes([0x00, 0x00, 0x01, stream_id])
    pes_length = len(optional) + len(payload)
    pes_data += struct.pack('>H', pes_length if pes_length < 65536 else 0)
    pes_data += optional + payload
    return pes_data


_PES_CC_STATE = {}


def pes_ts_packets(pes_data: bytes, pid: int, pcr_90khz: int = None) -> bytes:
    """Split PES data into TS packets.

    If ``pcr_90khz`` is given, the first packet carries an adaptation field
    with that PCR. The TS demuxer's prepcr queue holds back PES blocks until
    a PCR is observed (or 500ms of stream time elapses), so seeds with a
    single PES never reach the decoder unless we provide a PCR explicitly.

    Continuity counters are tracked per-PID across multiple calls so that
    repeated PES packets on the same PID do not look like discontinuities
    to the dvbpsi/TS demuxers.
    """
    out = b''
    offset = 0
    pusi = True
    cc = _PES_CC_STATE.get(pid, 0)
    while offset < len(pes_data):
        if pusi and pcr_90khz is not None:
            chunk = pes_data[offset: offset + 184 - 8]  # leave room for AF
            out += make_ts_packet(pid, chunk, pusi=True, cc=cc,
                                  pcr_90khz=pcr_90khz)
        else:
            chunk = pes_data[offset: offset + 184]
            out += make_ts_packet(pid, chunk, pusi=pusi, cc=cc)
        offset += len(chunk)
        pusi = False
        cc = (cc + 1) & 0x0F
    _PES_CC_STATE[pid] = cc
    return out


# ──────────────────────────────────────────────────
#  TS payload fragments
# ──────────────────────────────────────────────────

MPGV_PAYLOAD = bytes([
    0x00, 0x00, 0x01, 0xB3, 0x16, 0x00, 0xF0, 0x15,
    0xFF, 0xFF, 0xE0, 0x00,
    0x00, 0x00, 0x01, 0xB8, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0xFF, 0xFF,
    0x00, 0x00, 0x01, 0x01, 0x22, 0x00, 0x00,
])

H264_PAYLOAD = bytes([
    0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E,
    0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8,
    0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80,
    0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00,
    0x33, 0xFF,
])

HEVC_PAYLOAD = bytes([
    0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
    0xFF, 0xFF, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01,
    0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0xAF, 0x09,
])

MP2_PAYLOAD = bytes([
    0xFF, 0xFD, 0x90, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

MP3_PAYLOAD = bytes([
    0xFF, 0xFB, 0x90, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

AAC_ADTS_PAYLOAD = bytes([
    0xFF, 0xF1, 0x50, 0x80, 0x01, 0x7F, 0xFC,
    0x00, 0x00,
])

AC3_PAYLOAD = bytes([
    0x0B, 0x77,
    0x00, 0x00,
    0x04, 0x20,
    0x00, 0x00, 0x00, 0x00,
])

DTS_PAYLOAD = bytes([
    0x7F, 0xFE, 0x80, 0x01,
    0xFF, 0x1F, 0x00, 0x00, 0xFF, 0xE8,
])


# DVB subtitle PES payload — see generate_ts_seeds.py history for rationale.
def _dvbsub_seg(seg_type: int, page_id: int, data: bytes) -> bytes:
    return bytes([0x0F, seg_type]) + struct.pack('>HH', page_id, len(data)) + data


def _build_dvb_sub_payload(page_id: int = 1) -> bytes:
    out = bytes([0x20, 0x00])
    out += _dvbsub_seg(0x14, page_id,
                       bytes([0x10, 0x02, 0xCF, 0x02, 0x3F]))
    out += _dvbsub_seg(0x10, page_id,
                       bytes([0x05, 0x14,
                              0x00, 0xFF, 0x00, 0x00, 0x00, 0x00]))
    out += _dvbsub_seg(0x11, page_id,
                       bytes([0x00, 0x10,
                              0x00, 0x10, 0x00, 0x10,
                              0x4C, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    out += _dvbsub_seg(0x12, page_id,
                       bytes([0x00, 0x10,
                              0x00, 0xE1, 0x80, 0x80, 0x80, 0x80,
                              0x01, 0x21, 0xFF, 0x80, 0x80, 0x00]))
    _top = bytes([0x10, 0x00, 0x00, 0x00,
                  0x11, 0x00, 0x00,
                  0x12, 0x00, 0x00,
                  0x20, 0x00,
                  0x21, 0x00, 0x00,
                  0x22, 0x00, 0x00, 0x00, 0x00,
                  0xF0])
    out += _dvbsub_seg(0x13, page_id,
                       struct.pack('>H', 0x0000) + bytes([0x00])
                       + struct.pack('>HH', len(_top), 0) + _top)
    out += _dvbsub_seg(0x13, page_id,
                       struct.pack('>H', 0x0001) + bytes([0x40])
                       + bytes([0x02])
                       + struct.pack('>HH', 0x0041, 0x0042))
    out += _dvbsub_seg(0x16, page_id,
                       bytes([0x01, 0x10, 0x00, 0x00,
                              0x80, 0x80, 0x80, 0x00,
                              0xFF, 0x80, 0x80, 0x00]))
    out += _dvbsub_seg(0xFF, page_id, b'\x00\x00')
    out += _dvbsub_seg(0x80, page_id, b'')
    out += bytes([0xFF])
    return out


DVB_SUB_PAYLOAD = _build_dvb_sub_payload(page_id=1)
_DVB_SUB_PAD_TARGET = 170
DVB_SUB_PAYLOAD = DVB_SUB_PAYLOAD + bytes(
    [0xFF] * max(0, _DVB_SUB_PAD_TARGET - len(DVB_SUB_PAYLOAD)))


# ──────────────────────────────────────────────────
#  DVB subtitle — extended payloads exercising the
#  decode_object / dvbsub_render_pdata / dvbsub_pdataNbpp
#  RLE paths plus alternative_CLUT depth/gamut branches.
#  See modules/codec/dvbsub.c (~1800 lines, 7.2% in 2026-05-16
#  report).  All segment formats below follow ETSI EN 300-743.
# ──────────────────────────────────────────────────

# CLUT definition section.  Each entry header is:
#   8 bits id, 3 bits "type" mask (bit2=8b,bit1=4b,bit0=2b),
#   reserved 4 bits, 1 bit "full_range" flag.
# When full_range=1: 4*8 bits (Y/Cr/Cb/T).
# When full_range=0: 6+4+4+2 bits (Y/Cr/Cb/T compressed).
def _dvb_clut_entry(cid: int, type_mask: int, full: bool,
                    y: int, cr: int, cb: int, t: int) -> bytes:
    if full:
        return bytes([cid,
                      (type_mask & 0x07) << 5 | 0x01,
                      y & 0xFF, cr & 0xFF, cb & 0xFF, t & 0xFF])
    # 6+4+4+2 = 16 bits packed into 2 bytes
    b0 = ((y >> 2) & 0x3F) << 2 | ((cr >> 4) & 0x03)
    b1 = (((cr >> 6) & 0x03) << 6
          | ((cb >> 4) & 0x0F) << 2
          | ((t  >> 6) & 0x03))
    return bytes([cid,
                  (type_mask & 0x07) << 5 | 0x00,
                  b0, b1])


def _dvb_clut_seg(page_id: int, clut_id: int, entries: bytes) -> bytes:
    body = bytes([clut_id, 0x00]) + entries  # version=0
    return _dvbsub_seg(0x12, page_id, body)


def _dvb_pcs(page_id: int, regions: list, version: int = 0,
             state: int = 0x02) -> bytes:
    # state: 0=normal,1=acquisition,2=mode-change,3=reserved.
    body = bytes([0x14, (version & 0x0F) << 4 | (state & 0x03) << 2])
    for region_id, x, y in regions:
        body += bytes([region_id, 0xFF]) + struct.pack('>HH', x, y)
    return _dvbsub_seg(0x10, page_id, body)


def _dvb_region(page_id: int, region_id: int, *, width: int, height: int,
                depth: int, level_comp: int, clut_id: int, fill: bool,
                version: int = 0, obj_defs: list = ()) -> bytes:
    # depth: 1=2bpp, 2=4bpp, 3=8bpp.
    # level_comp: 1=2bpp,2=4bpp,3=8bpp.
    flags = (version & 0x0F) << 4 | (1 << 3 if fill else 0)
    body = bytes([region_id, flags])
    body += struct.pack('>HH', width, height)
    body += bytes([(level_comp & 0x07) << 5 | (depth & 0x07) << 2,
                   clut_id,
                   0x00,        # 8bpp pixel code for background
                   0x00,        # 4bpp (4 bits) | 2bpp (2 bits) bg | reserved
                   ])
    for obj_id, obj_type, ox, oy in obj_defs:
        body += struct.pack('>H', obj_id)
        body += bytes([(obj_type & 0x03) << 6 | 0x00 | ((ox >> 8) & 0x0F)])
        body += bytes([ox & 0xFF])
        body += bytes([((oy >> 8) & 0x0F)])
        body += bytes([oy & 0xFF])
        body += bytes([0x00])  # fg/bg pixel codes only for type 1/2
    return _dvbsub_seg(0x11, page_id, body)


# Encode raw bits for the pixel-data inner streams. The RLE specs in
# dvbsub.c make every switch branch reachable; we emit at least one of
# each so the function bodies of dvbsub_pdata{2,4,8}bpp are entered.
class _BitW:
    def __init__(self):
        self.bits = []
    def w(self, value, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)
    def out(self):
        # Pad to byte boundary with 0.
        while len(self.bits) % 8:
            self.bits.append(0)
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            v = 0
            for b in self.bits[i:i+8]:
                v = (v << 1) | b
            out.append(v)
        return bytes(out)


def _pdata2bpp_field() -> bytes:
    # color != 0 path
    w = _BitW(); w.w(0b01, 2)        # single px color 1
    # Switch1: 3+count + color
    w.w(0b00, 2); w.w(0b1, 1)        # zero color, switch1=1
    w.w(0b101, 3); w.w(0b10, 2)      # 3+5=8 px color 2
    # Switch2 case 0x02: 12+count + color
    w.w(0b00, 2); w.w(0b0, 1); w.w(0b1, 1); w.w(0b10, 2)
    w.w(0b0011, 4); w.w(0b11, 2)     # 12+3=15 px color 3
    # Switch2 case 0x03: 29+count + color
    w.w(0b00, 2); w.w(0b0, 1); w.w(0b1, 1); w.w(0b11, 2)
    w.w(0b00000101, 8); w.w(0b01, 2) # 29+5=34 px color 1
    # Switch2 case 0x01: 2 pixel run
    w.w(0b00, 2); w.w(0b0, 1); w.w(0b1, 1); w.w(0b01, 2)
    # Single pixel color 0
    w.w(0b00, 2); w.w(0b0, 1); w.w(0b0, 1)
    # End-of-string (Switch3 case 0x00)
    w.w(0b00, 2); w.w(0b0, 1); w.w(0b1, 1); w.w(0b00, 2)
    return w.out()


def _pdata4bpp_field() -> bytes:
    w = _BitW()
    w.w(0x5, 4)                        # color != 0 single px
    # Switch1==0 with count!=0 path: count = bs_read(3)+2
    w.w(0x0, 4); w.w(0b0, 1); w.w(0b011, 3)   # 3+2 = 5 px color 0
    # Switch1==1, Switch2==0 path: 4+count, color
    w.w(0x0, 4); w.w(0b1, 1); w.w(0b0, 1); w.w(0b10, 2); w.w(0x3, 4)
    # Switch1==1, Switch2==1, Switch3==0x0 path: 1 px color 0
    w.w(0x0, 4); w.w(0b1, 1); w.w(0b1, 1); w.w(0b00, 2)
    # Switch1==1, Switch2==1, Switch3==0x1 path: 2 px color 0
    w.w(0x0, 4); w.w(0b1, 1); w.w(0b1, 1); w.w(0b01, 2)
    # Switch1==1, Switch2==1, Switch3==0x2 path: 9+count, color
    w.w(0x0, 4); w.w(0b1, 1); w.w(0b1, 1); w.w(0b10, 2); w.w(0x4, 4); w.w(0x7, 4)
    # Switch1==1, Switch2==1, Switch3==0x3 path: 25+count, color
    w.w(0x0, 4); w.w(0b1, 1); w.w(0b1, 1); w.w(0b11, 2); w.w(0x02, 8); w.w(0x9, 4)
    # End-of-string (Switch1==0, count=0)
    w.w(0x0, 4); w.w(0b0, 1); w.w(0b000, 3)
    return w.out()


def _pdata8bpp_field() -> bytes:
    w = _BitW()
    w.w(0x42, 8)                       # color != 0 single px
    # Switch1==0 (zero color), count!=0 path: bs_read(7)
    w.w(0x00, 8); w.w(0b0, 1); w.w(0b0000110, 7)   # 6 px color 0
    # Switch1==1 path: bs_read(7) count, bs_read(8) color
    w.w(0x00, 8); w.w(0b1, 1); w.w(0b0001000, 7); w.w(0x55, 8)
    # End-of-string (Switch1==0, count=0)
    w.w(0x00, 8); w.w(0b0, 1); w.w(0b0000000, 7)
    return w.out()


def _dvb_object_pixmap(page_id: int, obj_id: int,
                       topfield: bytes, bottomfield: bytes) -> bytes:
    # 16 bits id, 4 bits version, 2 bits coding_method=0, 1 bit non_modify,
    # 1 bit reserved, 16 bits top_len, 16 bits bottom_len, payload(s).
    body = struct.pack('>H', obj_id)
    body += bytes([0x00])  # version=0 | coding_method=0 | non_modify=0 | rsv=0
    body += struct.pack('>HH', len(topfield), len(bottomfield))
    body += topfield + bottomfield
    return _dvbsub_seg(0x13, page_id, body)


def _dvb_object_chars(page_id: int, obj_id: int, chars: bytes) -> bytes:
    # coding_method=1 (chars): 16 bits id, 4 bits v, 2 bits cm=1,
    # 2 bits, 8 bits number_of_codes, then number_of_codes * 16 bits.
    body = struct.pack('>H', obj_id)
    body += bytes([0x40])  # version=0 | coding_method=1 | non_modify=0 | rsv=0
    body += bytes([len(chars)])
    for ch in chars:
        body += struct.pack('>H', ch)
    return _dvbsub_seg(0x13, page_id, body)


def _dvb_dds(page_id: int, *, windowed: bool, width: int, height: int,
             window: tuple = (0, 0, 0, 0)) -> bytes:
    # 4 bits version, 1 bit display_window_flag, 3 bits reserved,
    # 16 bits width-1, 16 bits height-1, optional 8x16 bits window.
    body = bytes([(1 if windowed else 0) << 3])
    body += struct.pack('>HH', max(0, width - 1), max(0, height - 1))
    if windowed:
        body += struct.pack('>HHHH', *window)
    return _dvbsub_seg(0x14, page_id, body)


def _dvb_alt_clut(page_id: int, clut_id: int, *,
                  output_bit_depth: int = 0,
                  gamut: int = 0,
                  entries: list = ()) -> bytes:
    # alternative_CLUT: 8 bits id, 4 bits version, 4 bits reserved,
    # CLUT_parameters (2 bits max-num, 2 bits comp-type, 3 bits bit-depth,
    # 1 bit rsv, 8 bits dynamic_range_and_colour_gamut), then entries.
    body = bytes([clut_id, 0x00])
    body += bytes([(0 << 6) | (0 << 4) | ((output_bit_depth & 0x07) << 1)])
    body += bytes([gamut & 0xFF])
    for y, cr, cb, t in entries:
        if output_bit_depth == 0x01:
            # 10-bit: 4 * 10 = 40 bits per entry = 5 bytes
            v = ((y & 0x3FF) << 30) | ((cr & 0x3FF) << 20) \
                | ((cb & 0x3FF) << 10) | (t & 0x3FF)
            body += v.to_bytes(5, 'big')
        else:
            body += bytes([y & 0xFF, cr & 0xFF, cb & 0xFF, t & 0xFF])
    return _dvbsub_seg(0x16, page_id, body)


def _build_dvb_sub_payload_rich(page_id: int = 1) -> bytes:
    """A DVB sub PES exercising:
       - display definition (DDS) with windowed=true (covers windowed branch)
       - page composition (PCS) with state=ACQUISITION + 3 regions
       - region composition x3 covering depths 1/2/3 (2bpp/4bpp/8bpp)
         each with multiple object_defs of type 0 (basic char) and 1 (composite)
       - CLUT definition with full and partial color ranges and entries
         setting type bits to fill c_2b / c_4b / c_8b storage classes
       - object data of coding_method=0 carrying both pdata2bpp/4bpp/8bpp
         RLE bitstreams in top and bottom fields
       - object data of coding_method=1 (char codes)
       - alternative_CLUT for the same clut_id with output_bit_depth=8 and
         gamut switching across DVBSUB_ST_COLORIMETRY_CDS/SDR_709/HDR_PQ/HDR_HLG
       - end_of_display + stuffing"""
    out = bytes([0x20, 0x00])

    # DDS — windowed=true with offsets within a 720x576 raster
    out += _dvb_dds(page_id, windowed=True, width=720, height=576,
                    window=(10, 700, 10, 560))

    # PCS — acquisition with three region defs
    out += _dvb_pcs(page_id, version=0, state=0x01,
                    regions=[(0x00, 0, 0),
                             (0x01, 100, 0),
                             (0x02, 0, 100)])

    # CLUT 0: type bit 0 (2b) + bit 1 (4b) + bit 2 (8b), entries with both
    # full-range and partial-range encodings.
    clut_entries = b''
    clut_entries += _dvb_clut_entry(0x00, type_mask=0x07, full=True,
                                    y=80, cr=128, cb=128, t=0)
    clut_entries += _dvb_clut_entry(0x01, type_mask=0x04, full=True,
                                    y=255, cr=128, cb=128, t=0xFF)
    clut_entries += _dvb_clut_entry(0x02, type_mask=0x02, full=False,
                                    y=128, cr=160, cb=160, t=0x80)
    clut_entries += _dvb_clut_entry(0x03, type_mask=0x01, full=False,
                                    y=0, cr=0, cb=0, t=0xFF)
    # y==0 special case path
    clut_entries += _dvb_clut_entry(0x04, type_mask=0x07, full=True,
                                    y=0, cr=100, cb=100, t=0x00)
    out += _dvb_clut_seg(page_id, clut_id=0, entries=clut_entries)

    # Three regions, one per depth.
    out += _dvb_region(page_id, region_id=0,
                       width=32, height=16, depth=1, level_comp=1,
                       clut_id=0, fill=True,
                       obj_defs=[(0x0010, 0, 0, 0),
                                 (0x0011, 1, 8, 0),
                                 (0x0012, 2, 16, 0)])
    out += _dvb_region(page_id, region_id=1,
                       width=32, height=16, depth=2, level_comp=2,
                       clut_id=0, fill=True,
                       obj_defs=[(0x0020, 0, 0, 0),
                                 (0x0021, 1, 8, 0)])
    out += _dvb_region(page_id, region_id=2,
                       width=32, height=16, depth=3, level_comp=3,
                       clut_id=0, fill=True,
                       obj_defs=[(0x0030, 0, 0, 0)])

    # Object data — three pixmap objects (2bpp/4bpp/8bpp) one per region.
    f2 = _pdata2bpp_field()
    f4 = _pdata4bpp_field()
    f8 = _pdata8bpp_field()
    # Each field is preceded/followed by 0x10/0x11/0x12 selector + optional
    # 0x20/0x21/0x22 (map-tables, ignored) + 0xF0 end-of-line; we wrap
    # everything to exercise dvbsub_render_pdata's switch on 0x10/0x11/0x12/
    # 0x20/0x21/0x22/0xF0.
    f2_wrap = bytes([0x10]) + f2 + bytes([0x20, 0x21, 0x22, 0xF0, 0x10]) + f2
    f4_wrap = bytes([0x11]) + f4 + bytes([0xF0, 0x11]) + f4
    f8_wrap = bytes([0x12]) + f8 + bytes([0xF0, 0x12]) + f8
    out += _dvb_object_pixmap(page_id, obj_id=0x0010, topfield=f2_wrap,
                              bottomfield=bytes([0x10]) + f2)
    # Bottom field empty -> duplicate top field path
    out += _dvb_object_pixmap(page_id, obj_id=0x0011, topfield=f2_wrap,
                              bottomfield=b'')
    out += _dvb_object_pixmap(page_id, obj_id=0x0020, topfield=f4_wrap,
                              bottomfield=bytes([0x11]) + f4)
    out += _dvb_object_pixmap(page_id, obj_id=0x0030, topfield=f8_wrap,
                              bottomfield=bytes([0x12]) + f8)

    # Character-coded object (coding_method=1)
    out += _dvb_object_chars(page_id, obj_id=0x0012,
                             chars=b'ABCDEF')
    out += _dvb_object_chars(page_id, obj_id=0x0021,
                             chars=b'XY')

    # Alternative CLUT — 8-bit depth, each iteration touches the
    # colorimetry switch in decode_object's render path indirectly via
    # default_clut + Color range = FULL.
    alt_entries = [(80, 128, 128, 0),
                   (255, 128, 128, 0xFF),
                   (160, 200, 100, 0x80)]
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x00,
                         gamut=0x00, entries=alt_entries)

    # Stuffing + end-of-display
    out += _dvbsub_seg(0xFF, page_id, b'\x00\x00\x00\x00')
    out += _dvbsub_seg(0x80, page_id, b'')

    # End-marker terminating the while-loop on sync_byte == 0x0F.
    out += bytes([0xFF])
    return out


DVB_SUB_PAYLOAD_RICH = _build_dvb_sub_payload_rich(page_id=1)
_DVB_SUB_RICH_PAD = 760
DVB_SUB_PAYLOAD_RICH = DVB_SUB_PAYLOAD_RICH + bytes(
    [0xFF] * max(0, _DVB_SUB_RICH_PAD - len(DVB_SUB_PAYLOAD_RICH)))


# Variant focused on alternative_CLUT branches (10-bit + colour-gamut
# enums) so all four DVBSUB_ST_COLORIMETRY_* cases run.
def _build_dvb_sub_altclut_payload(page_id: int = 1) -> bytes:
    out = bytes([0x20, 0x00])
    out += _dvb_dds(page_id, windowed=False, width=720, height=576)
    out += _dvb_pcs(page_id, version=0, state=0x01, regions=[(0x00, 0, 0)])
    # Define the CLUT first so alternative_CLUT updates an existing entry.
    out += _dvb_clut_seg(page_id, clut_id=0,
                         entries=_dvb_clut_entry(0x00, 0x07, True,
                                                  80, 128, 128, 0))
    out += _dvb_region(page_id, region_id=0, width=8, height=8, depth=3,
                       level_comp=3, clut_id=0, fill=True,
                       obj_defs=[(0x0030, 0, 0, 0)])
    out += _dvb_object_pixmap(page_id, obj_id=0x0030,
                              topfield=bytes([0x12]) + _pdata8bpp_field(),
                              bottomfield=b'')
    # 8-bit depth, walk every colorimetry enum.
    entries = [(64+i, 128, 128, 0) for i in range(8)]
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x00,
                         gamut=0x00, entries=entries)   # CDS-mapped
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x00,
                         gamut=0x01, entries=entries)   # SDR_2020
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x00,
                         gamut=0x02, entries=entries)   # HDR_PQ
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x00,
                         gamut=0x03, entries=entries)   # HDR_HLG
    # 10-bit path
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x01,
                         gamut=0x00, entries=[(0x300, 0x200, 0x200, 0)])
    # Error-path: invalid bit-depth (4) so error=true is taken.
    out += _dvb_alt_clut(page_id, clut_id=0, output_bit_depth=0x04,
                         gamut=0x00, entries=[(80, 128, 128, 0)])
    out += _dvbsub_seg(0x80, page_id, b'')
    out += bytes([0xFF])
    return out


DVB_SUB_PAYLOAD_ALTCLUT = _build_dvb_sub_altclut_payload(page_id=1)


# SCTE-27 subtitling section
_SCTE27_BMP = bytes([0x00,
                     0x00, 0x00,
                     0x00, 0x00, 0x00,
                     0x10, 0x01, 0x00])
_SCTE27_MSG = (
    bytes([0x00, 0x00, 0x00])
    + bytes([0x80])
    + bytes([0x00, 0x00, 0x00, 0x00])
    + bytes([0x10, 0x10])
    + bytes([0x00, len(_SCTE27_BMP)])
    + _SCTE27_BMP
)
_SCTE27_INNER = bytes([0x00]) + _SCTE27_MSG + bytes([0xDE, 0xAD, 0xBE, 0xEF])
_SCTE27_SECT_LEN = len(_SCTE27_INNER)
# SCTE-27 subtitle_section() per spec: section_syntax_indicator = 0
# (private_section / no MPEG CRC trailer).  Round-1 had 0xB0 which sets
# syntax_indicator=1 and causes dvbpsi to reject the section because the
# trailing 4 bytes are an SCTE-27 message field, not a valid MPEG CRC32.
SCTE27_PAYLOAD = (
    bytes([0xC6,
           0x30 | ((_SCTE27_SECT_LEN >> 8) & 0x0F),
           _SCTE27_SECT_LEN & 0xFF])
    + _SCTE27_INNER
)


PMT_PID    = 0x0100
VIDEO_PID  = 0x0101
AUDIO_PID  = 0x0102
SUBS_PID   = 0x0103
SDT_PID    = 0x0011


def seed_mpeg2_video() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x02, VIDEO_PID, b'')])
    pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, VIDEO_PID))


def seed_h264_video() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x1B, VIDEO_PID, b'')])
    pes = make_ts_pes(0xE0, H264_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, VIDEO_PID))


def seed_hevc_video() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x24, VIDEO_PID, b'')])
    pes = make_ts_pes(0xE0, HEVC_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, VIDEO_PID))


def seed_mpeg1_audio() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x03, AUDIO_PID, b'')])
    pes = make_ts_pes(0xC0, MP2_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_aac_audio() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x0F, AUDIO_PID, b'')])
    pes = make_ts_pes(0xC0, AAC_ADTS_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_ac3_audio() -> bytes:
    ac3_desc = bytes([0x05, 0x04, 0x41, 0x43, 0x2D, 0x33])
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x06, AUDIO_PID, ac3_desc)])
    pes = make_ts_pes(0xBD, AC3_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_dts_audio() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x06, AUDIO_PID, b'')])
    pes = make_ts_pes(0xBD, DTS_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def _dvb_sub_descriptor(page_id: int = 1) -> bytes:
    # subtitling_descriptor (tag 0x59), one entry, page composition page_id.
    return bytes([
        0x59, 0x08,
        0x65, 0x6E, 0x67,          # eng
        0x10,                       # subtitling_type = DVB
        (page_id >> 8) & 0xFF,      # composition_page_id
        page_id & 0xFF,
        (page_id >> 8) & 0xFF,      # ancillary_page_id (same here)
        page_id & 0xFF,
    ])


def seed_dvb_subtitle() -> bytes:
    sub_desc = _dvb_sub_descriptor(page_id=1)
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x06, SUBS_PID, sub_desc),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    subs_pes_a = make_ts_pes(0xBD, DVB_SUB_PAYLOAD, pts_90khz=1800)
    subs_pes_b = make_ts_pes(0xBD, DVB_SUB_PAYLOAD, pts_90khz=9000)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            pes_ts_packets(subs_pes_a, SUBS_PID) +
            pes_ts_packets(subs_pes_b, SUBS_PID))


def seed_dvb_subtitle_rich() -> bytes:
    """TS carrying the structurally-rich DVB sub PES that walks every
       segment type, both CLUT encodings, all three pixel-data RLE
       decoders, and the character-coded object branch."""
    sub_desc = _dvb_sub_descriptor(page_id=1)
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x06, SUBS_PID, sub_desc),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    # Send the rich payload twice — first packet establishes state, second
    # exercises the "skip duplicate version" and re-render paths.
    subs_pes_a = make_ts_pes(0xBD, DVB_SUB_PAYLOAD_RICH, pts_90khz=1800)
    subs_pes_b = make_ts_pes(0xBD, DVB_SUB_PAYLOAD_RICH, pts_90khz=9000)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            pes_ts_packets(subs_pes_a, SUBS_PID) +
            pes_ts_packets(subs_pes_b, SUBS_PID))


def seed_cea708_video() -> bytes:
    """TS carrying an H.264 PES whose payload is the full SPS+PPS+SEI(CC)
       +SEI(CC)+IDR sequence built by _build_h264_cea708_seed.  The TS
       demuxer + h264 packetizer combo is significantly more robust at
       reaching OutputPicture (and therefore SEI processing) than the raw
       h264 ES demuxer, so this is the path that actually drives
       modules/codec/cc.c and modules/codec/cea708.c."""
    h264 = cea708_h264_payload()
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x1B, VIDEO_PID, b'')])
    # Send two PES so the h264 packetizer hits an OutputPicture: a first
    # IDR (with our SEI) followed by a brand-new SPS/PPS/SEI/IDR which
    # triggers the picture-output path on the second slice arrival.
    pes_a = make_ts_pes(0xE0, h264, pts_90khz=900)
    pes_b = make_ts_pes(0xE0, h264, pts_90khz=4500)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes_a, VIDEO_PID, pcr_90khz=450) +
            pes_ts_packets(pes_b, VIDEO_PID))


def seed_dvb_subtitle_altclut() -> bytes:
    """TS exercising the alternative_CLUT depth/gamut branches."""
    sub_desc = _dvb_sub_descriptor(page_id=1)
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x06, SUBS_PID, sub_desc),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    subs_pes = make_ts_pes(0xBD, DVB_SUB_PAYLOAD_ALTCLUT, pts_90khz=1800)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            pes_ts_packets(subs_pes, SUBS_PID))


def seed_scte27() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x82, SUBS_PID, b''),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID) +
            _scte27_section_ts_packet([SCTE27_PAYLOAD], SUBS_PID))


def seed_with_sdt() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x02, VIDEO_PID, b'')])
    sdt = make_sdt(tsid=0x0001, orig_net=0x0001,
                   services={0x0001: ('Test Service', 0x01)})
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            psi_packet(sdt, SDT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID))


def seed_multi_program() -> bytes:
    PMT2_PID   = 0x0200
    VIDEO2_PID = 0x0201
    pat = make_pat([(0x0001, PMT_PID), (0x0002, PMT2_PID)])
    pmt1 = make_pmt(0x0001, VIDEO_PID,  [(0x02, VIDEO_PID,  b'')])
    pmt2 = make_pmt(0x0002, VIDEO2_PID, [(0x1B, VIDEO2_PID, b'')])
    video1_pes = make_ts_pes(0xE0, MPGV_PAYLOAD,  pts_90khz=0)
    video2_pes = make_ts_pes(0xE0, H264_PAYLOAD,  pts_90khz=0)
    return (psi_packet(pat,  0x0000) +
            psi_packet(pmt1, PMT_PID) +
            psi_packet(pmt2, PMT2_PID) +
            pes_ts_packets(video1_pes, VIDEO_PID) +
            pes_ts_packets(video2_pes, VIDEO2_PID))


def seed_multi_stream() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID,  b''),
        (0x03, AUDIO_PID,  b''),
        (0x06, SUBS_PID,   b''),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD,  pts_90khz=0)
    audio_pes = make_ts_pes(0xC0, MP2_PAYLOAD,   pts_90khz=900)
    subs_pes  = make_ts_pes(0xBD, DVB_SUB_PAYLOAD, pts_90khz=1800)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID) +
            pes_ts_packets(audio_pes, AUDIO_PID) +
            pes_ts_packets(subs_pes,  SUBS_PID))


# ATSC PSIP seeds: GA94 registration on the PMT switches the demuxer into
# ATSC mode and attaches MGT/STT dvbpsi decoders on PID 0x1FFB.
ATSC_BASE_PID = 0x1FFB


def _atsc_section(table_id: int, tid_ext: int, body: bytes,
                  protocol_version: int = 0) -> bytes:
    inner = struct.pack('>H', tid_ext) + bytes([0xC1, 0x00, 0x00,
                                                protocol_version]) + body
    section_length = len(inner) + 4
    hdr = bytes([table_id]) + struct.pack('>H', 0xF000 | section_length)
    full = hdr + inner
    return full + struct.pack('>I', crc32_mpeg(full))


def make_atsc_mgt(tables: list) -> bytes:
    body = struct.pack('>H', len(tables))
    for ttype, pid, version, byte_count in tables:
        body += struct.pack('>H', ttype)
        body += struct.pack('>H', 0xE000 | (pid & 0x1FFF))
        body += bytes([0xE0 | (version & 0x1F)])
        body += struct.pack('>I', byte_count)
        body += struct.pack('>H', 0xF000)
    body += struct.pack('>H', 0xF000)
    return _atsc_section(0xC7, 0x0000, body)


def make_atsc_stt(gps_seconds: int = 1_000_000_000) -> bytes:
    body = struct.pack('>I', gps_seconds)
    body += bytes([0])
    body += struct.pack('>H', 0)
    body += struct.pack('>H', 0xF000)
    return _atsc_section(0xCD, 0x0000, body)


def make_atsc_tvct() -> bytes:
    short_name = 'TestCh'.ljust(7, '\x00').encode('utf-16-be')
    chan = short_name
    chan += bytes([0xF0, 0x04, 0x01])
    chan += bytes([0x04])
    chan += struct.pack('>I', 0)
    chan += struct.pack('>H', 0x0001)
    chan += struct.pack('>H', 0x0001)
    chan += struct.pack('>H', 0xFC00)
    chan += struct.pack('>H', 0x00FF)
    chan += struct.pack('>H', 0xFC00)
    body = bytes([0x01]) + chan
    body += struct.pack('>H', 0xFC00)
    return _atsc_section(0xC8, 0x0001, body)


# ATSC A/65 multiple_string structure ([number_of_strings] then per-string:
# [lang(3)][number_of_segments] then per-segment: [compression][mode][bytes][..]).
# Compression must be 0 (NONE) for atsc_a65.c to actually decode; mode must
# be <= 0x06 (UNICODE_RANGE_END) for the UTF-16BE iconv path to run.
def _a65_segment(compression: int, mode: int, data: bytes) -> bytes:
    assert len(data) <= 0xFF
    return bytes([compression & 0xFF, mode & 0xFF, len(data) & 0xFF]) + data


def _a65_string(lang: bytes, segments: list) -> bytes:
    assert len(lang) == 3
    out = bytearray(lang)
    out.append(len(segments) & 0xFF)
    for s in segments:
        out += s
    return bytes(out)


def _a65_multiple_string(strings: list) -> bytes:
    out = bytearray([len(strings) & 0xFF])
    for s in strings:
        out += s
    return bytes(out)


# A/65 §6.10 Content Advisory descriptor (tag 0x87): rating regions w/
# rating dimensions and a multiple_string description.
def _atsc_content_advisory(description_text: bytes) -> bytes:
    region = bytes([0x01,             # rating region (US)
                    0x01,             # rated_dimensions
                    0x05,             # rating dimension index
                    0x03])            # rating value
    region += bytes([len(description_text)]) + description_text
    body = bytes([(1 & 0x3F) | 0xC0]) + region
    return bytes([0x87, len(body)]) + body


# A/65 §6.16 Extended Channel Name descriptor (tag 0xA0): just one
# multiple_string holding the long channel name.
def _atsc_extended_channel_name(name: bytes) -> bytes:
    return bytes([0xA0, len(name)]) + name


def make_atsc_tvct_rich() -> bytes:
    """TVCT with two channels:
       0xFE source carries an extended_channel_name descriptor that
         routes through atsc_a65_Decode_multiple_string,
       0xFF source carries no descriptors so we also exercise the
         short_name-only fallback path."""
    long_name = _a65_multiple_string([
        _a65_string(b'eng', [_a65_segment(0x00, 0x00, b'Test Channel One')])
    ])
    desc_a = _atsc_extended_channel_name(long_name)

    short_a = 'TestCh1'.encode('utf-16-be')
    chan_a = short_a
    chan_a += bytes([0xF0, 0x04, 0x01])
    chan_a += bytes([0x04])
    chan_a += struct.pack('>I', 0)
    chan_a += struct.pack('>H', 0x0001)
    chan_a += struct.pack('>H', 0x0001)
    chan_a += struct.pack('>H', 0xFC00)
    chan_a += struct.pack('>H', 0x00FE)            # source_id == 0xFE
    chan_a += struct.pack('>H', 0xFC00 | (len(desc_a) & 0x03FF))
    chan_a += desc_a

    short_b = 'TestCh2'.encode('utf-16-be')
    chan_b = short_b
    chan_b += bytes([0xF0, 0x04, 0x01])
    chan_b += bytes([0x04])
    chan_b += struct.pack('>I', 0)
    chan_b += struct.pack('>H', 0x0002)
    chan_b += struct.pack('>H', 0x0002)
    chan_b += struct.pack('>H', 0xFC00)
    chan_b += struct.pack('>H', 0x00FF)            # source_id == 0xFF
    chan_b += struct.pack('>H', 0xFC00)
    body = bytes([0x02]) + chan_a + chan_b
    body += struct.pack('>H', 0xFC00)              # outer additional_descriptors
    return _atsc_section(0xC8, 0x0001, body)


def make_atsc_eit_rich(source_id: int = 0x00FF) -> bytes:
    """EIT with two events, the second carrying a content_advisory
       descriptor that funnels its description through A/65 decoding."""
    title_a = _a65_multiple_string([
        _a65_string(b'eng', [_a65_segment(0x00, 0x00, b'Event A title')])
    ])
    event_a = struct.pack('>H', 0xC001)            # event_id 1
    event_a += struct.pack('>I', 1_000_000)         # start_time (GPS)
    event_a += bytes([0xC0, 0x00, 0x00, 0x3C])      # ETM_loc=00, length=60
    event_a += bytes([len(title_a)]) + title_a
    event_a += struct.pack('>H', 0xF000)            # descriptor_loop empty

    title_b = _a65_multiple_string([
        _a65_string(b'eng', [_a65_segment(0x00, 0x00, b'Event B title')])
    ])
    advisory_text = _a65_multiple_string([
        _a65_string(b'eng', [_a65_segment(0x00, 0x00, b'PG-13 advisory')])
    ])
    ca_desc = _atsc_content_advisory(advisory_text)
    event_b = struct.pack('>H', 0xC002)            # event_id 2
    event_b += struct.pack('>I', 1_000_120)         # start (later)
    event_b += bytes([0xC0, 0x00, 0x00, 0xB4])      # ETM_loc=00, length=180s
    event_b += bytes([len(title_b)]) + title_b
    event_b += struct.pack('>H', 0xF000 | (len(ca_desc) & 0x03FF)) + ca_desc

    body = bytes([0x02]) + event_a + event_b
    return _atsc_section(0xCB, source_id, body)


# A/65 ETT carries an ETM_id (32-bit) made of (source<<16 | event_id) for
# events and (source<<16) for channels, plus an extended_text_message that
# is itself an A/65 multiple_string.
def make_atsc_ett(etm_id: int, text_ms: bytes) -> bytes:
    body = struct.pack('>I', etm_id) + text_ms
    # ETT uses table_id 0xCC and table_id_extension is the ETT table type ID
    # (any value, here 0 — dvbpsi ETT raw callback uses ETM_id for matching).
    return _atsc_section(0xCC, 0x0000, body)


def seed_atsc_psip() -> bytes:
    """Full-fat ATSC PSIP stream:
       MGT → STT → TVCT (two channels, one w/ extended_channel_name) →
       two EITs across two PIDs → two ETT messages matching the two events
       on a third PID.  Covers ts_psip.c MGT/STT/VCT/EIT/ETT callbacks,
       ts_si.c never gets activated here because the PMT carries GA94 so
       the demuxer enters ATSC mode (see ts.c TS_STANDARD_ATSC)."""
    ga94 = bytes([0x05, 0x04, 0x47, 0x41, 0x39, 0x34])
    eit_pid_0 = 0x1D00
    eit_pid_1 = 0x1D01
    ett_pid_0 = 0x1D80
    ett_pid_1 = 0x1D81
    pat = make_pat([(0x0001, PMT_PID)])

    def make_pmt_with_outer(program_num: int, pcr_pid: int, outer_desc: bytes,
                            streams: list) -> bytes:
        body = struct.pack('>H', 0xE000 | pcr_pid)
        body += struct.pack('>H', 0xF000 | len(outer_desc)) + outer_desc
        for stype, es_pid, descs in streams:
            body += bytes([stype])
            body += struct.pack('>H', 0xE000 | es_pid)
            body += struct.pack('>H', 0xF000 | len(descs))
            body += descs
        return psi_section(0x02, program_num, body)

    pmt = make_pmt_with_outer(0x0001, VIDEO_PID, ga94,
                              [(0x02, VIDEO_PID, b'')])
    mgt = make_atsc_mgt([
        (0x0000, ATSC_BASE_PID, 0, 0),    # TVCT
        (0x0004, ATSC_BASE_PID, 0, 0),    # Channel ETT (CETT) base
        (0x0100, eit_pid_0,    0, 0),    # EIT_0
        (0x0101, eit_pid_1,    0, 0),    # EIT_1
        (0x0200, ett_pid_0,    0, 0),    # ETT_0
        (0x0201, ett_pid_1,    0, 0),    # ETT_1
    ])
    stt = make_atsc_stt()
    tvct = make_atsc_tvct_rich()
    eit0 = make_atsc_eit_rich(source_id=0x00FE)
    eit1 = make_atsc_eit_rich(source_id=0x00FF)

    # Long descriptions for both events; ETM_id = (source<<16) | event_id.
    long_a = _a65_multiple_string([
        _a65_string(b'eng', [_a65_segment(0x00, 0x00, b'Long ETT for event A')])
    ])
    long_b = _a65_multiple_string([
        _a65_string(b'eng', [_a65_segment(0x00, 0x00, b'Long ETT for event B')])
    ])
    ett_a = make_atsc_ett((0x00FE << 16) | 0xC001, long_a)
    ett_b = make_atsc_ett((0x00FF << 16) | 0xC002, long_b)

    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    # Section dispatch is driven by dvbpsi sub-decoders attached lazily as
    # tables arrive.  In particular:
    #   - The STT sub-decoder is attached at PSIP base setup time.
    #   - ATSC_STT_Callback's first call attaches the MGT decoder.
    #   - ATSC_MGT_Callback attaches the VCT and per-PID EIT/ETT decoders.
    #   - ATSC_EIT_Callback won't process anything until both p_stt and
    #     p_vct are already set on the base PSIP context.
    # We therefore inject STT first to bootstrap MGT, then MGT (which
    # attaches VCT + EIT/ETT decoders), then TVCT, then a second STT/MGT
    # round so the EIT/ETT sections that follow have a fully-populated
    # base context to satisfy ATSC_EIT_Callback's pre-conditions.
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            psi_packet(stt, ATSC_BASE_PID) +
            psi_packet(mgt, ATSC_BASE_PID) +
            psi_packet(tvct, ATSC_BASE_PID) +
            psi_packet(stt, ATSC_BASE_PID) +
            psi_packet(mgt, ATSC_BASE_PID) +
            psi_packet(tvct, ATSC_BASE_PID) +
            psi_packet(eit0, eit_pid_0) +
            psi_packet(eit1, eit_pid_1) +
            psi_packet(ett_a, ett_pid_0) +
            psi_packet(ett_b, ett_pid_1) +
            psi_packet(eit0, eit_pid_0) +
            psi_packet(eit1, eit_pid_1) +
            psi_packet(ett_a, ett_pid_0) +
            psi_packet(ett_b, ett_pid_1))


def seed_dvb_si() -> bytes:
    """Pure DVB stream (no GA94 → ts_si.c attaches SDT/EIT/TDT subdecoders).
       Covers ts_si.c EIT/TDT/TOT paths and SDT service-name decoding via
       dvb_charset that are not exercised by the existing 'with_sdt.ts'."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x02, VIDEO_PID, b'')])
    sdt = make_sdt(tsid=0x0001, orig_net=0x0001,
                   services={0x0001: ('Test Service', 0x01)})

    # EIT (DVB) — table_id 0x4E (present/following actual TS).
    # Section header structure differs from ATSC; for DVB EIT the section
    # carries: table_id, section_syntax + section_length, service_id (ext),
    # version + current_next, section_number, last_section_number,
    # transport_stream_id, original_network_id, segment_last_section_number,
    # last_table_id, then events.
    short_event_dr = bytes([0x4D, 0x12,             # tag, length
                            0x65, 0x6E, 0x67,        # ISO 639 'eng'
                            0x05] + list(b'Title')   # event_name_length, event_name
                           + [0x06] + list(b'Descr'))
    # 0x4D length should be 3 (lang) + 1 (event_name_length) + 5 (name) + 1 (text_length) + 5 (text) = 15 = 0x0F
    short_event_dr = (bytes([0x4D, 3 + 1 + len(b'Event Name') + 1 + len(b'Event Text'),
                             0x65, 0x6E, 0x67,
                             len(b'Event Name')]) + b'Event Name'
                      + bytes([len(b'Event Text')]) + b'Event Text')

    parental_dr = bytes([0x55, 0x04, ord('U'), ord('S'), ord('A'), 0x05])

    event = struct.pack('>H', 0xC001)           # event_id
    event += bytes([0xC0, 0x00, 0x00, 0x00, 0x00])  # start_time (MJD/UTC,5 bytes)
    event += bytes([0x00, 0x10, 0x00])          # duration BCD 0:10:00
    descs = short_event_dr + parental_dr
    # running_status=4 (running), free_CA=0, descriptors_loop_length(12)
    event += struct.pack('>H', (0x4 << 13) | (len(descs) & 0x0FFF))
    event += descs

    # DVB EIT body
    eit_body  = struct.pack('>H', 0x0001)       # tsid
    eit_body += struct.pack('>H', 0x0001)       # original_network_id
    eit_body += bytes([0x00, 0x4E])             # segment_last_sn, last_table_id
    eit_body += event

    # Build section
    section_length = 9 + len(eit_body) + 4      # 9 header + body + crc
    eit = bytes([0x4E])                          # table_id
    eit += struct.pack('>H', 0x8000 | 0x3000 | (section_length & 0x0FFF))
    eit += struct.pack('>H', 0x0001)             # service_id (= program)
    eit += bytes([0xC1, 0x00, 0x00])             # version/current_next/sn/last_sn
    eit += eit_body
    eit += struct.pack('>I', crc32_mpeg(eit))

    # TDT (table_id 0x70) carries 5 bytes of UTC time.
    tdt_payload = bytes([0xC0, 0x00, 0x00, 0x00, 0x00])
    tdt = bytes([0x70]) + struct.pack('>H', 0x7005) + tdt_payload  # syntax=0, len=5

    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            psi_packet(sdt, SDT_PID) +
            psi_packet(eit, 0x0012) +              # DVB EIT PID
            psi_packet(tdt, 0x0014))              # DVB TDT PID


# ──────────────────────────────────────────────────
# Round 2: SCTE-27 enhanced subtitle bitmaps
# ──────────────────────────────────────────────────
#
# scte27.c::DecodeSimpleBitmap has four mutually-exclusive style branches:
#   - outline_style == 0: plain bitmap (existing round 1 seed covers this).
#   - outline_style == 1: outline draw — needs `is_framed=1` to be useful and
#     uses outline_thickness with a circle stamp.
#   - outline_style == 2: shadow draw — uses shadow_right/shadow_bottom.
#   - outline_style == 3: reserved (skip 24 bits, plain bitmap render).
# Each variant exercises a different rendering loop. The four bytes
# preceding DecodeSubtitleMessage carry display_standard (0..3 = 480/576/720/1080)
# and a subtitle_type==1 flag — switching display_standard exercises the
# four `frame_duration` branches at scte27.c:364-391.
#
# We also generate one segmentation_overlay variant that splits the
# subtitle_message across two SCTE-27 sections (index=0 then index=last)
# so the xrealloc/concat path at scte27.c:445-470 runs.

class _BitWriter:
    def __init__(self):
        self.buf = 0
        self.nbits = 0
        self.out = bytearray()
    def write(self, n, v):
        v &= (1 << n) - 1
        self.buf = (self.buf << n) | v
        self.nbits += n
        while self.nbits >= 8:
            self.nbits -= 8
            self.out.append((self.buf >> self.nbits) & 0xFF)
    def bytes(self):
        if self.nbits:
            self.out.append((self.buf << (8 - self.nbits)) & 0xFF)
            self.nbits = 0
        return bytes(self.out)


def _scte27_color(bs, y, alpha_flag, v, u):
    bs.write(5, y & 0x1F)
    bs.write(1, alpha_flag & 1)
    bs.write(5, v & 0x1F)
    bs.write(5, u & 0x1F)


def _scte27_bitmap_body(*, is_framed, outline_style):
    """Return the simple_bitmap_section payload (bit-packed)."""
    bs = _BitWriter()
    bs.write(5, 0)
    bs.write(1, 1 if is_framed else 0)
    bs.write(2, outline_style)
    _scte27_color(bs, y=0x10, alpha_flag=1, v=0x08, u=0x08)
    bs.write(12, 8)
    bs.write(12, 8)
    bs.write(12, 24)
    bs.write(12, 24)
    if is_framed:
        bs.write(12, 4)
        bs.write(12, 4)
        bs.write(12, 28)
        bs.write(12, 28)
        _scte27_color(bs, y=0x05, alpha_flag=1, v=0x10, u=0x10)
    if outline_style == 1:
        bs.write(4, 0)
        bs.write(4, 2)
        _scte27_color(bs, y=0x1F, alpha_flag=1, v=0x00, u=0x00)
    elif outline_style == 2:
        bs.write(4, 1)
        bs.write(4, 1)
        _scte27_color(bs, y=0x00, alpha_flag=1, v=0x00, u=0x00)
    elif outline_style == 3:
        bs.write(24, 0)
    bs.write(16, 0)
    for _ in range(2):
        bs.write(1, 1); bs.write(3, 4); bs.write(5, 8)
    for _ in range(2):
        bs.write(2, 0b01); bs.write(6, 16)
    bs.write(3, 0b001); bs.write(4, 4)
    bs.write(4, 0b0001); bs.write(2, 1)
    return bs.bytes()


def _scte27_subtitle_message(*, display_standard, pre_clear, is_framed,
                             outline_style, display_duration=8):
    bitmap = _scte27_bitmap_body(is_framed=is_framed,
                                 outline_style=outline_style)
    # data[3] = pre_clear<<7 | display_standard
    flags3 = (0x80 if pre_clear else 0x00) | (display_standard & 0x1F)
    subtitle_type = 1
    block_length = len(bitmap)
    header = bytes([
        0x00, 0x00, 0x00,
        flags3,
        0x00, 0x00, 0x00, 0x00,
        (subtitle_type << 4) | ((display_duration >> 8) & 0x07),
        display_duration & 0xFF,
        (block_length >> 8) & 0xFF,
        block_length & 0xFF,
    ])
    return header + bitmap


def _scte27_section(*, payload, segmentation_overlay=False,
                    seg_id=0, last=0, index=0):
    """Wrap an SCTE-27 message in an MPEG section."""
    if segmentation_overlay:
        body = (bytes([0x40])
                + struct.pack('>H', seg_id)
                + bytes([(last >> 4) & 0xFF,
                         ((last & 0x0F) << 4) | ((index >> 8) & 0x0F),
                         index & 0xFF])
                + payload
                + bytes([0xDE, 0xAD, 0xBE, 0xEF]))
    else:
        body = bytes([0x00]) + payload + bytes([0xDE, 0xAD, 0xBE, 0xEF])
    section_length = len(body)
    # syntax_indicator=0 (private_section, no CRC) — see SCTE27_PAYLOAD note.
    return (bytes([0xC6,
                   0x30 | ((section_length >> 8) & 0x0F),
                   section_length & 0xFF])
            + body)


def _scte27_pes_payload(sections, pad_to=170):
    """Legacy helper retained for callers; SCTE-27 transport is sections,
    not PES, but the section bytes are identical to what we used to pad."""
    raw = b''.join(sections)
    return raw + bytes([0xFF] * max(0, pad_to - len(raw)))


def _scte27_section_ts_packet(sections, pid: int, cc: int = 0) -> bytes:
    """Wrap one or more SCTE-27 sections directly in a single TS packet.

    SCTE-27 (PMT stream_type 0x82) is delivered as TS_TRANSPORT_SECTIONS
    inside the TS payload (pointer_field + section bytes), NOT inside a PES.
    Wrapping in a PES (as round-1's seed_scte27 did) means
    GatherSectionsData / ts_sections_processor_Push never see the section
    header and SCTE27_Section_Callback in ts_scte.c is never invoked.
    """
    raw = b''.join(sections) if isinstance(sections, (list, tuple)) else sections
    payload = bytes([0x00]) + raw   # pointer_field = 0
    assert len(payload) <= 184, \
        f"SCTE-27 section payload {len(payload)} bytes too large for a single TS packet"
    return make_ts_packet(pid, payload, pusi=True, cc=cc)


def _seed_scte27_variant(sections):
    """sections may be a single bytes object (one section), a list of sections,
    or — for backwards compatibility with the old PES-padded payload — a
    bytes blob already containing concatenated sections + 0xFF padding."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x82, SUBS_PID, b''),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID) +
            _scte27_section_ts_packet(sections, SUBS_PID))


def seed_scte27_framed() -> bytes:
    msg = _scte27_subtitle_message(display_standard=1, pre_clear=True,
                                   is_framed=True, outline_style=0)
    return _seed_scte27_variant([_scte27_section(payload=msg)])


def seed_scte27_outline() -> bytes:
    msg = _scte27_subtitle_message(display_standard=2, pre_clear=True,
                                   is_framed=True, outline_style=1)
    return _seed_scte27_variant([_scte27_section(payload=msg)])


def seed_scte27_shadow() -> bytes:
    msg = _scte27_subtitle_message(display_standard=3, pre_clear=True,
                                   is_framed=True, outline_style=2)
    return _seed_scte27_variant([_scte27_section(payload=msg)])


def seed_scte27_reserved_style() -> bytes:
    """outline_style==3: takes the 24-bit-skip branch + falls through to
    DEFAULT display_standard (5)."""
    msg = _scte27_subtitle_message(display_standard=5, pre_clear=False,
                                   is_framed=False, outline_style=3)
    return _seed_scte27_variant([_scte27_section(payload=msg)])


def seed_scte27_segmented() -> bytes:
    msg = _scte27_subtitle_message(display_standard=0, pre_clear=True,
                                   is_framed=True, outline_style=1)
    split = max(8, len(msg) // 2)
    sec0 = _scte27_section(payload=msg[:split], segmentation_overlay=True,
                           seg_id=0x1234, last=1, index=0)
    sec1 = _scte27_section(payload=msg[split:], segmentation_overlay=True,
                           seg_id=0x1234, last=1, index=1)
    return _seed_scte27_variant([sec0, sec1])


# ──────────────────────────────────────────────────
#  TS extensions targeting 0%-covered PMT setup paths in
#  modules/demux/mpeg/ts_psi.c and the dependent
#  ts_metadata.c / ts_arib.c files.
# ──────────────────────────────────────────────────
#
# As of the 2026-05-20 OSS-Fuzz report ts_psi.c sat at 44% line coverage
# and the following PMT-stream-setup functions were entirely 0%:
#
#   * PMTSetupEsHDMV          — Blu-ray HDMV registration, dispatches by
#                               stream type 0x80…0x92/0xEA/0xA1/0xA2
#   * PMTSetupEs0x83, 0xA0, 0xD1, 0xEA — non-HDMV variants of those types
#   * SetupMetadataDescriptors / Metadata_stream_processor_New
#                             — Metadata descriptor (0x26) driving
#                               ts_metadata.c (whole file at 0%)
#   * ParsePMTPrivateRegistrations + TS_PMT_REGISTRATION_ARIB branch
#                             — ARIB STD-B10 detection (descriptors 0x09
#                               CA_id=0x05, 0xC1, 0xF6); ts_arib.c is
#                               also 0%.
#
# The seeds below build minimal valid TS streams that walk those branches
# during PMT parsing. They reuse the existing make_ts_packet / psi_packet
# / make_pat machinery used elsewhere in this file.


def make_pmt_with_program_info(program_num: int, pcr_pid: int,
                               program_info: bytes, streams: list) -> bytes:
    """Like make_pmt but with program-level descriptors before the per-ES
       loop. Required for HDMV registration / ARIB triggers / etc."""
    body = struct.pack('>H', 0xE000 | pcr_pid)
    body += struct.pack('>H', 0xF000 | (len(program_info) & 0x0FFF))
    body += program_info
    for stype, es_pid, descs in streams:
        body += bytes([stype])
        body += struct.pack('>H', 0xE000 | es_pid)
        body += struct.pack('>H', 0xF000 | (len(descs) & 0x0FFF))
        body += descs
    return psi_section(0x02, program_num, body)


def _ts_registration_dr(rgs: bytes) -> bytes:
    assert len(rgs) == 4
    return bytes([0x05, 0x04]) + rgs


def _ts_ca_dr(ca_system_id: int, ca_pid: int = 0x1FFF) -> bytes:
    return bytes([0x09, 0x04]) + struct.pack('>HH',
                                             ca_system_id,
                                             0xE000 | (ca_pid & 0x1FFF))


def _ts_pad_to_min_packets(stream: bytes, min_packets: int = 4) -> bytes:
    """Append NULL packets (PID=0x1FFF, 0xFF stuffing) until the stream
       contains at least min_packets TS packets. ts.c::DetectPacketSize
       peeks 4*188 sync bytes before accepting a stream, so 3-packet
       seeds are rejected outright."""
    assert len(stream) % 188 == 0
    null_pkt = bytes([0x47, 0x1F, 0xFF, 0x10]) + bytes([0xFF] * 184)
    while len(stream) // 188 < min_packets:
        stream += null_pkt
    return stream


def _ts_metadata_dr() -> bytes:
    """Metadata_descriptor (tag 0x26) declaring ID3 application_format and
       format identifiers — triggers SetupMetadataDescriptors's ID3
       carriage path."""
    body  = struct.pack('>H', 0xFFFF)          # metadata_application_format
    body += b'ID3 '                             # metadata_application_format_identifier
    body += bytes([0xFF])                       # metadata_format = 0xFF (extended)
    body += b'ID3 '                             # metadata_format_identifier
    body += bytes([0x01])                       # metadata_service_id
    body += bytes([0x00])                       # flags (decoder_config_flags<<4)
    return bytes([0x26, len(body)]) + body


def seed_ts_bluray_hdmv() -> bytes:
    """HDMV-registered PMT carrying every Blu-ray stream type whose branch
       lives inside PMTSetupEsHDMV: 0x80 (LPCM), 0x81 (AC-3), 0x82/0xA2
       (DTS), 0x83 (TrueHD), 0x84/0xA1 (E-AC-3), 0x85/0x86 (DTS-HD),
       0x90 (PGS), 0x91 (IGS), 0x92 (Text-ST), 0xEA (VC-1)."""
    pat = make_pat([(0x0001, PMT_PID)])
    hdmv_dr = _ts_registration_dr(b'HDMV')
    streams = [
        (0x02, VIDEO_PID, b''),
        (0x80, 0x0110, b''),
        (0x81, 0x0111, b''),
        (0x82, 0x0112, b''),
        (0x83, 0x0113, b''),
        (0x84, 0x0114, b''),
        (0x85, 0x0115, b''),
        (0x86, 0x0116, b''),
        (0x90, 0x0190, b''),
        (0x91, 0x0191, b''),
        (0x92, 0x0192, b''),
        (0xEA, 0x01EA, b''),
        (0xA1, 0x01A1, b''),
        (0xA2, 0x01A2, b''),
    ]
    pmt = make_pmt_with_program_info(0x0001, VIDEO_PID, hdmv_dr, streams)
    pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    stream = (psi_packet(pat, 0x0000) +
              psi_packet(pmt, PMT_PID) +
              pes_ts_packets(pes, VIDEO_PID, pcr_90khz=0))
    return _ts_pad_to_min_packets(stream)


def seed_ts_arib_pmt() -> bytes:
    """PMT carrying the three descriptors that flip the TS demuxer into
       TS_STANDARD_ARIB (ParsePMTRegistrations / i_arib_score_flags==0x07):
       CA descriptor with system_id 0x05, descriptor 0xC1, descriptor 0xF6.
       Activating ARIB exercises ARIB-specific branches in ts_psi.c and
       the data_component_descriptor (0xFD) decode in ts_arib.c."""
    pat = make_pat([(0x0001, PMT_PID)])
    arib_pi = (_ts_ca_dr(0x0005) +
               bytes([0xC1, 0x01, 0x00]) +
               bytes([0xF6, 0x01, 0x00]))
    # data_component_descriptor (tag 0xFD) with component_id 0x0008 (=ARIB
    # caption) so the per-ES private descriptor path also fires.
    dcd = bytes([0xFD, 0x03, 0x00, 0x08, 0x3D])
    streams = [
        (0x02, VIDEO_PID, b''),
        (0x06, 0x0103, dcd),
    ]
    pmt = make_pmt_with_program_info(0x0001, VIDEO_PID, arib_pi, streams)
    pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    stream = (psi_packet(pat, 0x0000) +
              psi_packet(pmt, PMT_PID) +
              pes_ts_packets(pes, VIDEO_PID, pcr_90khz=0))
    return _ts_pad_to_min_packets(stream)


def seed_ts_metadata_id3() -> bytes:
    """PMT with stream_type 0x15 (Metadata in PES) + Metadata_descriptor
       (0x26) advertising ID3 carriage. ts_psi.c invokes
       SetupMetadataDescriptors → Metadata_stream_processor_New, and the
       PES blocks get routed through ts_metadata.c
       (Metadata_stream_processor_Push)."""
    pat = make_pat([(0x0001, PMT_PID)])
    metadata_pid = 0x0103
    streams = [
        (0x02, VIDEO_PID, b''),
        (0x15, metadata_pid, _ts_metadata_dr()),
    ]
    pmt = make_pmt(0x0001, VIDEO_PID, streams)
    pes_video = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    # ID3v2.4 tag (size-syncsafe = 0x18 bytes of frames): a single TIT2
    # frame holding "Title" so ID3TAG_Parse_Handler runs against real data.
    id3 = b'ID3\x04\x00\x00\x00\x00\x00\x18'
    id3 += b'TIT2'                              # frame id
    id3 += struct.pack('>I', 0x0e)              # syncsafe size
    id3 += b'\x00\x00'                          # flags
    id3 += b'\x03'                              # encoding = UTF-8
    id3 += b'Title\x00\x00\x00\x00\x00\x00\x00\x00'
    # Metadata PES uses stream_id 0xFC (metadata stream) per H.222.0
    pes_md = make_ts_pes(0xFC, id3, pts_90khz=900)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes_video, VIDEO_PID, pcr_90khz=0) +
            pes_ts_packets(pes_md, metadata_pid))


def seed_ts_private_stream_types() -> bytes:
    """PMT without a Blu-ray registration but with stream types 0x83
       (LPCM), 0xA0 (MS-CODEC), 0xD1 (Dirac), 0xEA (VC-1) and 0x21
       (JPEG 2000 video) — each routes through its own per-type
       PMTSetupEs0xXX setup function, all of which sit at 0% coverage
       outside the HDMV path. The 0x21 stream carries a J2K_video
       descriptor (tag 0x32) so SetupJ2KDescriptors also fires."""
    pat = make_pat([(0x0001, PMT_PID)])
    j2k_dr = bytes([0x32, 0x18,
                    0x10, 0x00,                # profile_and_level
                    0x00, 0x00, 0x07, 0x80,    # horizontal_size
                    0x00, 0x00, 0x04, 0x38,    # vertical_size
                    0x00, 0x00, 0x00, 0x00,    # max_bit_rate
                    0x00, 0x00, 0x00, 0x00,    # max_buffer_size
                    0x00, 0x00,                # DEN_frame_rate
                    0x00, 0x19,                # NUM_frame_rate
                    0x00, 0x00])               # rest reserved
    streams = [
        (0x02, VIDEO_PID, b''),
        (0x83, 0x0103, b''),
        (0xA0, 0x01A0, b''),
        (0xD1, 0x01D1, b''),
        (0xEA, 0x01EA, b''),
        (0x21, 0x0121, j2k_dr),
    ]
    pmt = make_pmt(0x0001, VIDEO_PID, streams)
    pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    stream = (psi_packet(pat, 0x0000) +
              psi_packet(pmt, PMT_PID) +
              pes_ts_packets(pes, VIDEO_PID, pcr_90khz=0))
    return _ts_pad_to_min_packets(stream)


TS_SEEDS = {
    'mpeg2_video.ts':  seed_mpeg2_video,
    'h264_video.ts':   seed_h264_video,
    'hevc_video.ts':   seed_hevc_video,
    'mpeg1_audio.ts':  seed_mpeg1_audio,
    'aac_audio.ts':    seed_aac_audio,
    'ac3_audio.ts':    seed_ac3_audio,
    'dts_audio.ts':    seed_dts_audio,
    'dvb_subtitle.ts': seed_dvb_subtitle,
    'dvb_subtitle_rich.ts':    seed_dvb_subtitle_rich,
    'dvb_subtitle_altclut.ts': seed_dvb_subtitle_altclut,
    'scte27.ts':       seed_scte27,
    'scte27_framed.ts':   seed_scte27_framed,
    'scte27_outline.ts':  seed_scte27_outline,
    'scte27_shadow.ts':   seed_scte27_shadow,
    'scte27_reserved.ts': seed_scte27_reserved_style,
    'scte27_segmented.ts': seed_scte27_segmented,
    'with_sdt.ts':     seed_with_sdt,
    'multi_program.ts': seed_multi_program,
    'multi_stream.ts': seed_multi_stream,
    'atsc_psip.ts':    seed_atsc_psip,
    'dvb_si.ts':       seed_dvb_si,
    'cea708_video.ts': lambda: seed_cea708_video(),
    'bluray_hdmv.ts':       seed_ts_bluray_hdmv,
    'arib_pmt.ts':          seed_ts_arib_pmt,
    'metadata_id3.ts':      seed_ts_metadata_id3,
    'private_streams.ts':   seed_ts_private_stream_types,
}


def gen_ts(root):
    outdir = os.path.join(root, 'seeds', 'ts')
    os.makedirs(outdir, exist_ok=True)
    for filename, generator in TS_SEEDS.items():
        reset_psi_cc()
        data = generator()
        assert len(data) % 188 == 0, f'{filename}: length {len(data)} not multiple of 188'
        path = os.path.join(outdir, filename)
        with open(path, 'wb') as f:
            f.write(data)
        print(f'  seeds/ts/{filename}: {len(data)} bytes ({len(data) // 188} TS packets)')


# ──────────────────────────────────────────────────
#  PS (Program Stream) seed (modules/codec/spudec/parse.c)
# ──────────────────────────────────────────────────
#
# The upstream vlc-fuzz-corpus seeds/ps/dvd_subtitle.vob has the correct
# PS+PES wrapping but a malformed SPU header (i_spu_size=8192 with ~40 bytes
# of payload). The spudec packetizer holds the block waiting for 8192 bytes
# that never arrive, so parse.c (ParsePacket / ParseControlSeq / ParseRLE)
# never runs. This generator emits a structurally complete DVD SPU PES.

def make_ps_pack_header(scr_90khz: int = 0, mux_rate: int = 0x1869F) -> bytes:
    base = scr_90khz & ((1 << 33) - 1)
    ext = 0
    b = bytes([
        0x40 | ((base >> 27) & 0x38) | 0x04 | ((base >> 28) & 0x03),
        (base >> 20) & 0xFF,
        ((base >> 12) & 0xF8) | 0x04 | ((base >> 13) & 0x03),
        (base >> 5) & 0xFF,
        ((base << 3) & 0xF8) | 0x04 | ((ext >> 7) & 0x03),
        ((ext << 1) & 0xFE) | 0x01,
        (mux_rate >> 14) & 0xFF,
        (mux_rate >> 6) & 0xFF,
        ((mux_rate << 2) & 0xFC) | 0x03,
        0xF8,
    ])
    return bytes([0x00, 0x00, 0x01, 0xBA]) + b


def make_ps_pes(stream_id: int, payload: bytes, pts_90khz: int = 9000) -> bytes:
    """PES packet with mandatory length (PS-style; asserts <65536)."""
    p = pts_90khz
    pts_bytes = bytes([
        0x21 | ((p >> 29) & 0x0E),
        (p >> 22) & 0xFF,
        0x01 | ((p >> 14) & 0xFE),
        (p >> 7) & 0xFF,
        0x01 | ((p << 1) & 0xFE),
    ])
    optional = bytes([0x80, 0x80, len(pts_bytes)]) + pts_bytes
    pes_length = len(optional) + len(payload)
    assert pes_length < 65536
    return bytes([0x00, 0x00, 0x01, stream_id]) \
        + struct.pack('>H', pes_length) \
        + optional + payload


def make_dvd_spu() -> bytes:
    """Build a minimal but structurally complete DVD subtitle SPU body."""
    rle = bytes([0x40, 0x00, 0x00, 0x00,
                 0x40, 0x00, 0x00, 0x00])
    rle_size = len(rle)
    control_offset = 4 + rle_size

    seq1_off = control_offset
    seq2_off = seq1_off + (4
                           + 1 + 2
                           + 1 + 2
                           + 1 + 6
                           + 1 + 4
                           + 1
                           + 1)
    seq1 = struct.pack('>HH', 0, seq2_off)
    seq1 += bytes([0x03, 0x32, 0x10])
    seq1 += bytes([0x04, 0x0F, 0x00])
    seq1 += bytes([0x05, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10])
    seq1 += bytes([0x06]) + struct.pack('>HH', 4, 4 + rle_size // 2)
    seq1 += bytes([0x01])
    seq1 += bytes([0xFF])

    seq2 = struct.pack('>HH', 100, seq2_off)
    seq2 += bytes([0x02])
    seq2 += bytes([0xFF])

    body = rle + seq1 + seq2
    spu_size = 4 + len(body)
    assert spu_size <= 0xFFFF
    return struct.pack('>HH', spu_size, control_offset) + body


SUB_STREAM_ID_DVD_SPU0 = 0x20


def seed_dvd_subtitle() -> bytes:
    spu = make_dvd_spu()
    pes_payload = bytes([SUB_STREAM_ID_DVD_SPU0]) + spu
    spu_pes = make_ps_pes(0xBD, pes_payload, pts_90khz=9000)
    padding_pes = bytes([0x00, 0x00, 0x01, 0xBE]) + struct.pack('>H', 8) + bytes([0xFF] * 8)
    return (make_ps_pack_header(scr_90khz=0)
            + spu_pes
            + make_ps_pack_header(scr_90khz=4500)
            + padding_pes
            + bytes([0x00, 0x00, 0x01, 0xB9]))


def gen_ps(root):
    outdir = os.path.join(root, 'seeds', 'ps')
    os.makedirs(outdir, exist_ok=True)
    data = seed_dvd_subtitle()
    path = os.path.join(outdir, 'dvd_subtitle.vob')
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  seeds/ps/dvd_subtitle.vob: {len(data)} bytes')


# ──────────────────────────────────────────────────
#  HEIF / AVIF seeds (modules/demux/mp4/heif.c)
# ──────────────────────────────────────────────────

def box(fourcc: bytes, payload: bytes) -> bytes:
    assert len(fourcc) == 4
    size = 8 + len(payload)
    return struct.pack('>I', size) + fourcc + payload


def fullbox(fourcc: bytes, version: int, flags: int, payload: bytes) -> bytes:
    head = bytes([version]) + struct.pack('>I', flags)[1:]
    return box(fourcc, head + payload)


def ftyp(major: bytes, compat: list) -> bytes:
    body = major + struct.pack('>I', 0) + b''.join(compat)
    return box(b'ftyp', body)


def hdlr(handler: bytes) -> bytes:
    return fullbox(b'hdlr', 0, 0,
                   struct.pack('>I', 0) + handler + bytes(12) + b'\x00')


def pitm(item_id: int) -> bytes:
    return fullbox(b'pitm', 0, 0, struct.pack('>H', item_id))


def infe(item_id: int, item_type: bytes, name: bytes = b'') -> bytes:
    payload = struct.pack('>HH', item_id, 0) + item_type + name + b'\x00'
    return fullbox(b'infe', 2, 0, payload)


def iinf(items: list) -> bytes:
    payload = struct.pack('>H', len(items)) + b''.join(items)
    return fullbox(b'iinf', 0, 0, payload)


def iloc(items: list, mdat_offset: int) -> bytes:
    payload = bytes([0x44, 0x00])
    payload += struct.pack('>H', len(items))
    cur = mdat_offset
    for item_id, length in items:
        payload += struct.pack('>HHHH', item_id, 0, 0, 1)
        payload += struct.pack('>II', cur, length)
        cur += length
    return fullbox(b'iloc', 1, 0, payload)


def iref_dimg(from_id: int, to_ids: list) -> bytes:
    body = struct.pack('>HH', from_id, len(to_ids))
    body += b''.join(struct.pack('>H', i) for i in to_ids)
    return fullbox(b'iref', 0, 0, box(b'dimg', body))


def ispe(width: int, height: int) -> bytes:
    return fullbox(b'ispe', 0, 0, struct.pack('>II', width, height))


def pixi(channels: list) -> bytes:
    return fullbox(b'pixi', 0, 0,
                   bytes([len(channels)]) + bytes(channels))


def ipco(props: list) -> bytes:
    return box(b'ipco', b''.join(props))


def ipma(assoc: list) -> bytes:
    payload = struct.pack('>I', len(assoc))
    for item_id, indices in assoc:
        payload += struct.pack('>HB', item_id, len(indices))
        payload += bytes([0x80 | (i & 0x7F) for i in indices])
    return fullbox(b'ipma', 0, 0, payload)


def iprp(ipco_box: bytes, ipma_box: bytes) -> bytes:
    return box(b'iprp', ipco_box + ipma_box)


def meta(children: list) -> bytes:
    body = hdlr(b'pict') + b''.join(children)
    return fullbox(b'meta', 0, 0, body)


def seed_heic_basic() -> bytes:
    img_data = bytes([0x00, 0x00, 0x00, 0x02, 0x40, 0x01])
    iinf_box = iinf([infe(1, b'hvc1', b'IMG\x00')])
    pitm_box = pitm(1)
    ipco_box = ipco([ispe(64, 64), pixi([8, 8, 8])])
    ipma_box = ipma([(1, [1, 2])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(img_data))], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iprp_box])
    ftyp_box = ftyp(b'heic', [b'mif1', b'heic'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(img_data))], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iprp_box])
    mdat_box = box(b'mdat', img_data)
    return ftyp_box + meta_box + mdat_box


def seed_avif_basic() -> bytes:
    img_data = bytes([0x12, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00])
    iinf_box = iinf([infe(1, b'av01', b'AV1\x00')])
    pitm_box = pitm(1)
    ipco_box = ipco([ispe(16, 16), pixi([8, 8, 8])])
    ipma_box = ipma([(1, [1, 2])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(img_data))], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iprp_box])
    ftyp_box = ftyp(b'avif', [b'mif1', b'avif'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(img_data))], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iprp_box])
    mdat_box = box(b'mdat', img_data)
    return ftyp_box + meta_box + mdat_box


def seed_heic_grid() -> bytes:
    tile_data = bytes([0x00, 0x00, 0x00, 0x02, 0x40, 0x01]) * 2
    grid_body = bytes([0x00, 0x00, 0x00, 0x01]) + struct.pack('>HH', 16, 8)
    iinf_box = iinf([
        infe(1, b'grid', b'GRID\x00'),
        infe(10, b'hvc1', b'T1\x00'),
        infe(11, b'hvc1', b'T2\x00'),
    ])
    pitm_box = pitm(1)
    iref_box = iref_dimg(1, [10, 11])
    ipco_box = ipco([ispe(16, 8)])
    ipma_box = ipma([(1, [1]), (10, [1]), (11, [1])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(grid_body)),
                        (10, len(tile_data) // 2),
                        (11, len(tile_data) // 2)], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iref_box, iprp_box])
    ftyp_box = ftyp(b'heic', [b'mif1', b'heic'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(grid_body)),
                     (10, len(tile_data) // 2),
                     (11, len(tile_data) // 2)], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iref_box, iprp_box])
    mdat_box = box(b'mdat', grid_body + tile_data)
    return ftyp_box + meta_box + mdat_box


HEIF_SEEDS = {
    'heic_basic.heic': seed_heic_basic,
    'avif_basic.avif': seed_avif_basic,
    'heic_grid.heic':  seed_heic_grid,
}


def heif_dictionary() -> str:
    tokens = [
        b'ftyp', b'mif1', b'msf1', b'heic', b'heix', b'avif', b'avis',
        b'meta', b'hdlr', b'pict', b'pitm', b'iinf', b'infe', b'iloc',
        b'iref', b'dimg', b'thmb', b'cdsc', b'iprp', b'ipco', b'ipma',
        b'ispe', b'pixi', b'colr', b'irot', b'imir', b'clap', b'idat',
        b'mdat', b'grid', b'iovl', b'hvc1', b'av01', b'avc1', b'jpeg',
        b'hvcC', b'av1C', b'avcC',
    ]
    lines = ['# HEIF / ISOBMFF box / item-type tokens']
    for t in tokens:
        lines.append('"' + ''.join('\\x%02x' % b for b in t) + '"')
    return '\n'.join(lines) + '\n'


def gen_heif(root):
    seed_dir = os.path.join(root, 'seeds', 'heif')
    dict_dir = os.path.join(root, 'dictionaries')
    os.makedirs(seed_dir, exist_ok=True)
    os.makedirs(dict_dir, exist_ok=True)
    for filename, gen in HEIF_SEEDS.items():
        data = gen()
        with open(os.path.join(seed_dir, filename), 'wb') as f:
            f.write(data)
        print(f'  seeds/heif/{filename}: {len(data)} bytes')
    with open(os.path.join(dict_dir, 'heif.dict'), 'w') as f:
        f.write(heif_dictionary())
    print('  dictionaries/heif.dict written')


# ──────────────────────────────────────────────────
#  rawdv / vc1 / cdg / mus seeds + dictionaries
# ──────────────────────────────────────────────────

def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  wrote {path}: {len(data)} bytes")


def gen_avi(root):
    """Structured AVI (RIFF) seeds for modules/demux/avi.

    The upstream vlc-fuzz-corpus seeds/avi/* (divx/h264/mjpg/mp3/pcm/mono8 ...)
    only exercise compressed-codec video and PCM audio, leaving large parts of
    avi.c, libavi.c and bitmapinfoheader.h cold. These seeds drive the stream
    *type* branches that have no upstream coverage:

      - Uncompressed RGB (BI_RGB 24/8bpp + palette) and BI_BITFIELDS video,
        exercising ParseBitmapInfoHeader's RGB/palette/mask paths
        (bitmapinfoheader.h) and the bottom-up "flipped" frame handling.
      - DXSB (DivX/XSUB) subtitle track: SPU_ES setup plus the demux-time
        Xsub timestamp parser (ExtractXsubSampleInfo / AVI_PeekSample /
        AVI_GetXsubSampleTimeAt), all previously 0%.
      - 'txts' subtitle attachment -> AVI_ExtractSubtitle.
      - 'iavs'/'ivas' DV stream -> AVI_DvHandleAudio.
      - WAVE_FORMAT_EXTENSIBLE audio -> WAVEFORMATEXTENSIBLE SubFormat branch.
      - QNAP proprietary fourcc ('w264' ...) -> IsQNAPCodec + AVI_SendFrame
        header stripping (needs INFO meta so p_sys->meta is set).
      - 'vprp' chunk -> aspect-ratio handling.
      - OpenDML multi-RIFF ('AVIX') -> the AVI_ChunkReadRoot multi-RIFF path.

    Note: the fuzz harness' memory stream is always (fast)seekable and demux
    controls are off, so avi.c Seek()/Demux_UnSeekable() and the AVI_IndexLoad
    superindex parser are unreachable here regardless of input -- these seeds
    deliberately do not target them.
    """
    def fcc(s):
        b = s.encode("latin-1"); assert len(b) == 4; return b

    def chunk(cid, data):
        out = fcc(cid) + struct.pack("<I", len(data)) + data
        return out + b"\x00" if (len(data) & 1) else out  # word alignment

    def lst(listtype, *chunks):
        body = fcc(listtype) + b"".join(chunks)
        return fcc("LIST") + struct.pack("<I", len(body)) + body

    def riff(fourcc, *chunks):
        body = fcc(fourcc) + b"".join(chunks)
        return fcc("RIFF") + struct.pack("<I", len(body)) + body

    def avih(width, height, streams, totalframes=1, usperframe=40000):
        return struct.pack("<14I", usperframe, 0, 0, 0x10, totalframes, 0,
                           streams, 0, width, height, 0, 0, 0, 0)

    def strh(typ, handler, scale=1, rate=25, length=1, samplesize=0):
        # 12 dwords (48B read by libavi) + rcFrame (4x int16) = 56B canonical
        return (fcc(typ) + fcc(handler) +
                struct.pack("<11I", 0, 0, 0, scale, rate, 0, length, 0, 0,
                            samplesize, 0) +
                struct.pack("<4h", 0, 0, 0, 0))

    def bih(width, height, bitcount, compression, extra=b"", clrused=0):
        comp = (compression if isinstance(compression, int)
                else struct.unpack("<I", fcc(compression))[0])
        return (struct.pack("<I", 40 + len(extra)) +          # biSize
                struct.pack("<ii", width, height) +
                struct.pack("<HH", 1, bitcount) +
                struct.pack("<I", comp) +
                struct.pack("<I", 0) +                        # biSizeImage
                struct.pack("<ii", 0, 0) +
                struct.pack("<II", clrused, 0) + extra)

    def wfx(fmttag, channels=2, rate=44100, bits=16, blockalign=4, extra=b""):
        body = (struct.pack("<H", fmttag) + struct.pack("<H", channels) +
                struct.pack("<I", rate) + struct.pack("<I", rate * blockalign) +
                struct.pack("<H", blockalign) + struct.pack("<H", bits))
        if fmttag != 0x0001 or extra:                         # non-PCM -> cbSize
            body += struct.pack("<H", len(extra)) + extra
        return body

    def strl(strh_data, strf_id, strf_data, extra_chunks=b""):
        return lst("strl", chunk("strh", strh_data),
                   chunk(strf_id, strf_data), extra_chunks)

    def movi_chunk(stream, twocc, data):
        return chunk(f"{stream:02d}{twocc}", data)

    def build(streams, movi_chunks, extra_hdrl=b"", width=64, height=48,
              nframes=1):
        hdrl = lst("hdrl", chunk("avih", avih(width, height, len(streams),
                                              nframes)),
                   *streams, extra_hdrl)
        return riff("AVI ", hdrl, lst("movi", *movi_chunks))

    seeds = {}

    # BI_RGB 24bpp, positive height -> b_flipped + BGR24 chroma
    seeds["rgb24_flipped.avi"] = build(
        [strl(strh("vids", "DIB "), "strf", bih(8, 6, 24, 0))],
        [movi_chunk(0, "db", bytes([0x10, 0x20, 0x30]) * (8 * 6))],
        width=8, height=6)

    # BI_RGB 8bpp + 256-colour palette -> RGBP palette branch
    pal = b"".join(struct.pack("<BBBB", i, i, i, 0) for i in range(256))
    seeds["rgb8_palette.avi"] = build(
        [strl(strh("vids", "DIB "), "strf", bih(8, 6, 8, 0, extra=pal,
                                                clrused=256))],
        [movi_chunk(0, "db", bytes(range(48)))], width=8, height=6)

    # BI_BITFIELDS 16bpp + RGB565 masks -> known_chroma match
    seeds["bitfields_565.avi"] = build(
        [strl(strh("vids", "\x00\x00\x00\x00"), "strf",
              bih(8, 6, 16, 3, extra=struct.pack("<III", 0xF800, 0x07E0, 0x001F)))],
        [movi_chunk(0, "db", b"\x00" * 96)], width=8, height=6)

    # BI_BITFIELDS with extra < 12 bytes -> "bogus mask size, assume BI_RGB"
    seeds["bitfields_bogus.avi"] = build(
        [strl(strh("vids", "\x00\x00\x00\x00"), "strf",
              bih(8, 6, 16, 3, extra=b"\x00\x00\x00\x00"))],
        [movi_chunk(0, "db", b"\x00" * 96)], width=8, height=6)

    # DXSB subtitle: stream0 real video so AVI_GetVideoTrackForXsub succeeds,
    # stream1 DXSB -> SPU_ES + demux-time Xsub timestamp parsing.
    xsub = b"\x00" * 8 + b"[00:00:01.000-00:00:05.000]" + b"\x00" * 16
    seeds["dxsb_xsub.avi"] = build(
        [strl(strh("vids", "MJPG", length=2), "strf", bih(64, 48, 24, "MJPG")),
         strl(strh("vids", "DXSB", length=2), "strf", bih(720, 480, 24, "DXSB"))],
        [movi_chunk(0, "dc", b"\xff\xd8\xff\xd9"), movi_chunk(1, "dc", xsub),
         movi_chunk(0, "dc", b"\xff\xd8\xff\xd9"), movi_chunk(1, "dc", xsub)],
        width=720, height=480, nframes=2)

    # 'txts' subtitle attachment -> AVI_ExtractSubtitle (needs strn name)
    seeds["txts_attachment.avi"] = build(
        [strl(strh("txts", "\x00\x00\x00\x00"), "strf", bih(0, 0, 0, 0),
              extra_chunks=chunk("strn", b"subtitle track\x00"))],
        [movi_chunk(0, "tx", b"Hello subtitle\x00")])

    # 'iavs' DV stream -> VLC_CODEC_DV + AVI_DvHandleAudio
    seeds["dv_iavs.avi"] = build(
        [strl(strh("iavs", "dvsd"), "strf", bih(720, 480, 24, "dvsd"))],
        [movi_chunk(0, "dc", b"\x1f\x07\x00" * 40)], width=720, height=480)

    # WAVE_FORMAT_EXTENSIBLE audio -> WAVEFORMATEXTENSIBLE SubFormat branch
    guid = (struct.pack("<I", 0x0001) +
            b"\x00\x00\x10\x00\x80\x00\x00\xaa\x00\x38\x9b\x71")
    ext = struct.pack("<H", 16) + struct.pack("<I", 0x3) + guid
    seeds["extensible_audio.avi"] = build(
        [strl(strh("auds", "\x00\x00\x00\x00", samplesize=4), "strf",
              wfx(0xFFFE, channels=2, rate=48000, blockalign=4, extra=ext))],
        [movi_chunk(0, "wb", b"\x00" * 64)])

    # QNAP fourcc -> IsQNAPCodec + AVI_SendFrame header strip (INFO sets meta)
    qframe = b"QVR\x00" + b"\x00" * 52 + b"\x00\x00\x00\x01\x67"
    seeds["qnap_w264.avi"] = build(
        [strl(strh("vids", "w264"), "strf", bih(320, 240, 24, "w264"))],
        [movi_chunk(0, "dc", qframe)],
        extra_hdrl=lst("INFO", chunk("ISFT", b"QNAP\x00")),
        width=320, height=240)

    # 'vprp' chunk -> aspect-ratio handling
    vprp = chunk("vprp", struct.pack("<9I", 0, 0, 0, 0x00040003, 64, 48, 0, 0, 1) +
                 struct.pack("<4I", 0, 0, 0, 0))
    seeds["vprp_video.avi"] = build(
        [strl(strh("vids", "MJPG"), "strf", bih(64, 48, 24, "MJPG"),
              extra_chunks=vprp)],
        [movi_chunk(0, "dc", b"\xff\xd8\xff\xd9")])

    # OpenDML: a trailing RIFF 'AVIX' segment -> multi-RIFF detection
    avix = riff("AVIX", lst("movi", movi_chunk(0, "db", b"\x10\x20\x30" * 48)))
    seeds["multi_riff.avi"] = seeds["rgb24_flipped.avi"] + avix

    for name, data in seeds.items():
        _write(os.path.join(root, "seeds/avi", name), data)

    # Extend (not replace) the upstream avi.dict with tokens for the new paths.
    dict_path = os.path.join(root, "dictionaries", "avi.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "a") as f:
        f.write("\n# --- appended by generate_seeds.gen_avi ---\n")
        for tok in ["strn", "vprp", "DXSB", "iavs", "ivas", "txts",
                    "DIB ", "w264", "q264", "Q264", "wMP4", "dvsd"]:
            f.write('"%s"\n' % tok)
        f.write('"\\x03\\x00\\x00\\x00"\n')   # BI_BITFIELDS compression
        f.write('"\\xfe\\xff"\n')             # WAVE_FORMAT_EXTENSIBLE tag
        f.write('"[00:00:00.000-00:00:00.000]"\n')  # Xsub timestamp template


def gen_es(root):
    """Raw elementary-stream audio seeds for modules/demux/mpeg/es.c.

    es.c registers the "Audio ES" demuxer with shortcuts mpga/mp3/m4a/mp4a/
    aac/ac3/a52/eac3/dts/mlp/thd and probes each codec via AacProbe / MpgaProbe
    / A52Probe / EA52Probe / DtsProbe / MlpProbe / ThdProbe. The upstream
    vlc-fuzz-corpus only ships seeds/mp3 and seeds/dts, so the AAC, AC-3,
    E-AC-3, MLP and TrueHD probe + demux paths are entirely uncovered.

    Each seed dir name matches an es.c shortcut, so the OSS-Fuzz harness
    (target name -> demux_New name) force-selects es.c with that hint; the
    probe is then taken as forced, and valid sync frames drive OpenCommon()
    and the Demux() loop. Header fields are crafted to satisfy the sync
    checks exactly:
      - AC-3 (a52): 0x0B77, byte5>>3 == bsid 8 (<=10 -> AC-3); fscod=0,
        frmsizcod=0 -> 128-byte frames.
      - E-AC-3 (eac3): 0x0B77, bsid 16 (11..16 -> E-AC-3); frmsiz=63 ->
        i_size = 2*(63+1) = 128.
      - AAC (aac): 7-byte ADTS headers (0xFFF sync, no CRC), valid
        frame_length, fed to the mpeg4audio packetizer.
      - MLP/TrueHD (mlp/thd): MlpCheckSync/ThdCheckSync require bytes[4..7]
        == F8 72 6F BB / BA.
    These header parsers compute frame sizes / sample counts from attacker
    bytes -- classic OOB-read/overflow surface in es.c and the audio
    packetizers it instantiates.
    """
    def adts_frame(payload_len=24, freq_idx=4, chan=2, profile=1):
        frame_len = 7 + payload_len
        h = bytearray(7)
        h[0] = 0xFF
        h[1] = 0xF1                                  # MPEG-4, layer 0, no CRC
        h[2] = ((profile & 3) << 6) | ((freq_idx & 0xF) << 2) | ((chan >> 2) & 1)
        h[3] = ((chan & 3) << 6) | ((frame_len >> 11) & 3)
        h[4] = (frame_len >> 3) & 0xFF
        h[5] = ((frame_len & 7) << 5) | 0x1F
        h[6] = 0xFC
        return bytes(h) + bytes(payload_len)

    def ac3_frame():
        # fscod=0, frmsizcod=0 -> 128-byte frame; bsid 8 -> AC-3 dispatch
        return bytes([0x0B, 0x77, 0, 0, 0, 0x40, 0, 0]) + bytes(120)

    def eac3_frame():
        bits = []
        def put(val, n):
            for i in range(n - 1, -1, -1):
                bits.append((val >> i) & 1)
        put(0x0B77, 16)   # syncword
        put(0, 2)         # strmtyp
        put(0, 3)         # substreamid
        put(63, 11)       # frmsiz -> i_size = 128
        put(0, 2)         # fscod (48k)
        put(3, 2)         # numblkscod
        put(0, 3)         # acmod
        put(0, 1)         # lfeon
        put(16, 5)        # bsid (11..16 -> E-AC-3)
        while len(bits) % 8:
            bits.append(0)
        out = bytearray()
        for i in range(0, len(bits), 8):
            b = 0
            for k in range(8):
                b = (b << 1) | bits[i + k]
            out.append(b)
        return bytes(out).ljust(128, b"\x00")

    def mlp_frame(sync_last):
        f = bytearray(128)
        f[0] = 0xF0; f[1] = 0x40                     # check-nibble + au_length
        f[4] = 0xF8; f[5] = 0x72; f[6] = 0x6F; f[7] = sync_last
        return bytes(f)

    def rep(fn, n):
        return b"".join(fn() for _ in range(n))

    seeds = {
        "aac":  {"adts.aac": rep(lambda: adts_frame(24), 16),
                 "adts_small.aac": rep(lambda: adts_frame(8), 24)},
        "a52":  {"ac3.a52": rep(ac3_frame, 12)},
        "eac3": {"eac3.eac3": rep(eac3_frame, 12)},
        "mlp":  {"mlp.mlp": rep(lambda: mlp_frame(0xBB), 8)},
        "thd":  {"truehd.thd": rep(lambda: mlp_frame(0xBA), 8)},
    }
    dicts = {
        "aac":  ['"\\xff\\xf1"', '"\\xff\\xf9"', '"ADIF"'],
        "a52":  ['"\\x0b\\x77"'],
        "eac3": ['"\\x0b\\x77"'],
        "mlp":  ['"\\xf8\\x72\\x6f\\xbb"'],
        "thd":  ['"\\xf8\\x72\\x6f\\xba"'],
    }
    for tgt, files in seeds.items():
        for name, data in files.items():
            _write(os.path.join(root, "seeds", tgt, name), data)
        dict_path = os.path.join(root, "dictionaries", tgt + ".dict")
        os.makedirs(os.path.dirname(dict_path), exist_ok=True)
        with open(dict_path, "w") as f:
            f.write("\n".join(dicts[tgt]) + "\n")


def gen_rawdv(root):
    # modules/demux/rawdv.c: NTSC frame = 120000 bytes, PAL = 144000.
    DV_NTSC_FRAME_SIZE = 10 * 150 * 80
    seed = bytearray(DV_NTSC_FRAME_SIZE)
    seed[80 * 6 + 80 * 16 * 3 + 3] = 0x50  # plausible AAUX pack header
    _write(os.path.join(root, "seeds/rawdv/minimal_ntsc.dv"), bytes(seed))

    pal = bytearray(12 * 150 * 80)
    pal[3] = 0x80  # dsf bit -> PAL
    _write(os.path.join(root, "seeds/rawdv/minimal_pal.dv"), bytes(pal))

    dict_path = os.path.join(root, "dictionaries/rawdv.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "w") as f:
        f.write('# Raw DV identifiers / AAUX pack tags (SMPTE 314M)\n')
        for tag in [0x50, 0x51, 0x52, 0x53, 0x60, 0x61, 0x62, 0x63]:
            f.write(f'"\\x{tag:02x}"\n')
    print(f"  wrote {dict_path}")


def gen_vc1(root):
    seq_hdr = b"\x00\x00\x01\x0f"
    payload = bytes([0xC0, 0x04, 0xA0, 0x00, 0x10, 0x00, 0x00, 0x00])
    entrypoint = b"\x00\x00\x01\x0e" + bytes([0xC0, 0x00, 0x00, 0x00])
    frame = b"\x00\x00\x01\x0d" + bytes([0x00] * 32)
    eos = b"\x00\x00\x01\x1f"
    _write(os.path.join(root, "seeds/vc1/minimal.vc1"),
           seq_hdr + payload + entrypoint + frame + eos)
    _write(os.path.join(root, "seeds/vc1/two_frames.vc1"),
           seq_hdr + payload + entrypoint + frame + frame + eos)

    dict_path = os.path.join(root, "dictionaries/vc1.dict")
    with open(dict_path, "w") as f:
        f.write('# VC-1 start codes (SMPTE 421M-2006 Annex E)\n')
        for sc in [0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x1F, 0x1E, 0x1D]:
            f.write(f'"\\x00\\x00\\x01\\x{sc:02x}"\n')
        f.write('"\\x00\\x00\\x01"\n')
    print(f"  wrote {dict_path}")


def gen_cdg(root):
    def cmd(instruction, data):
        pkt = bytearray(24)
        pkt[0] = 0x09
        pkt[1] = instruction & 0x3f
        for i, b in enumerate(data[:16]):
            pkt[4 + i] = b
        return bytes(pkt)

    frame = b"".join([
        cmd(1, [0x00] + [0x00] * 15),
        cmd(2, [0x07] + [0x00] * 15),
        cmd(30, list(range(0, 32, 2))),
        cmd(6,  [0x01, 0x00, 0x05, 0x08] + [0xff] * 12),
    ])
    _write(os.path.join(root, "seeds/cdg/minimal.cdg"), frame * 4)

    frame2 = b"".join([
        cmd(31, list(range(8, 40, 2))),
        cmd(20, [0x00, 0x01, 0x01] + [0] * 13),
        cmd(24, [0x00, 0x02, 0x02] + [0] * 13),
        cmd(38, [0x00, 0x07, 0x00, 0x00] + [0xaa] * 12),
    ])
    _write(os.path.join(root, "seeds/cdg/scrolls.cdg"), frame2 * 3)

    dict_path = os.path.join(root, "dictionaries/cdg.dict")
    with open(dict_path, "w") as f:
        f.write('# CDG command opcode (buf[0] & 0x3f == 0x09) plus instruction selectors\n')
        f.write('"\\x09\\x01"\n')
        f.write('"\\x09\\x02"\n')
        f.write('"\\x09\\x06"\n')
        f.write('"\\x09\\x14"\n')
        f.write('"\\x09\\x18"\n')
        f.write('"\\x09\\x1c"\n')
        f.write('"\\x09\\x1e"\n')
        f.write('"\\x09\\x1f"\n')
        f.write('"\\x09\\x26"\n')
    print(f"  wrote {dict_path}")


def gen_mus(root):
    # The libfuzzer harness picks the demuxer module from the binary-name
    # suffix (`vlc-demux-dec-libfuzzer-<dirname>`). The DMX music demuxer
    # module is named "dmxmus" upstream — not "mus" — so seeds placed in
    # seeds/dmxmus/ would be passed to demux_New(... "mus" ...) and that call
    # fails with "cannot create demultiplexer: mus", never reaching
    # modules/demux/dmxmus.c. Use the actual module name.
    MAGIC = b"MUS\x1A"

    def header(primaries: int, secondaries: int, instc: int,
               event_bytes_len: int) -> bytes:
        hdrlen = 16 + 2 * instc
        return (
            MAGIC
            + struct.pack("<H", event_bytes_len)
            + struct.pack("<H", hdrlen)
            + struct.pack("<H", primaries)
            + struct.pack("<H", secondaries)
            + struct.pack("<H", instc)
            + b"\x00\x00"
        )

    events1 = bytes([0x10, 0x3C, 0x60])
    seed1 = header(primaries=1, secondaries=0, instc=0,
                   event_bytes_len=len(events1)) + events1
    _write(os.path.join(root, "seeds/dmxmus/minimal_play.mus"), seed1)

    instc = 2
    patch_list = struct.pack("<HH", 0x0001, 0x0010)
    events2 = bytes([
        0x40, 0x00, 0x40,
        0x40, 0x03, 0x60,
        0x30, 0x42,
        0x10, 0xC8, 0x7F,
        0xA0, 0x80, 0x05,
        0x50,
        0x40, 0x0F, 0x00,
        0x60,
    ])
    seed2 = header(primaries=2, secondaries=1, instc=instc,
                   event_bytes_len=len(events2)) + patch_list + events2
    _write(os.path.join(root, "seeds/dmxmus/controls.mus"), seed2)

    # Round 2 — comprehensive event stream. The previous seeds covered only a
    # handful of MUS_CTRL_* values; this one walks every documented event type
    # and every HandleControl/HandleControlValue branch so the switch
    # statements in dmxmus.c:165 and :194 are exercised.
    # Event-byte layout: high nibble = type<<4, low nibble = channel.
    #   0x00 release | 0x10 play | 0x20 pitch | 0x30 control |
    #   0x40 control_value | 0x50 measure_end | 0x60 track_end | 0x70 dummy.
    # Setting bit 7 on the event byte signals a VLQ delay follows.
    primaries3 = 4
    secondaries3 = 3
    instc3 = 6
    patch_list3 = b''.join(struct.pack('<HH', p, 0x0010 + p)
                           for p in range(instc3))
    events3 = bytes([
        # PLAY with running-volume on channel 0 (buf[1]&0x80=1 → also reads volume)
        0x10, 0x80 | 60, 0x60,
        # MUS_EV_DUMMY (type 7) — single extra byte
        0x70, 0x00,
        # CONTROL_VALUE on channel 1: every documented num (0..9)
        0x41, 0x00, 0x42,    # MUS_CTRL_PROGRAM_CHANGE
        0x41, 0x01, 0x10,    # MUS_CTRL_BANK_SELECT (returns NULL)
        0x41, 0x02, 0x40,    # MUS_CTRL_MODULATION
        0x41, 0x03, 0x60,    # MUS_CTRL_VOLUME
        0x41, 0x04, 0x55,    # MUS_CTRL_PAN
        0x41, 0x05, 0x4F,    # MUS_CTRL_EXPRESSION
        0x41, 0x06, 0x33,    # MUS_CTRL_REVERB
        0x41, 0x07, 0x22,    # MUS_CTRL_CHORUS
        0x41, 0x08, 0x77,    # MUS_CTRL_PEDAL_HOLD
        0x41, 0x09, 0x05,    # MUS_CTRL_PEDAL_SOFT
        # CONTROL_VALUE with num >= 10 falls through to HandleControl
        0x41, 0x0A, 0x00,    # → MUS_CTRL_SOUND_OFF in HandleControl
        0x41, 0x0B, 0x00,    # → MUS_CTRL_NOTES_OFF
        0x41, 0x0C, 0x00,    # → MUS_CTRL_MONO
        0x41, 0x0D, 0x00,    # → MUS_CTRL_POLY
        0x41, 0x0E, 0x00,    # → MUS_CTRL_RESET
        0x41, 0x0F, 0x00,    # → MUS_CTRL_EVENT
        0x41, 0x55, 0x00,    # → default "unknown control"
        # CONTROL (type 3) directly — must hit each branch too
        0x32, 0x0A,          # MUS_CTRL_SOUND_OFF
        0x32, 0x0B,          # MUS_CTRL_NOTES_OFF
        0x32, 0x0C,          # MUS_CTRL_MONO
        0x32, 0x0D,          # MUS_CTRL_POLY
        0x32, 0x0E,          # MUS_CTRL_RESET
        0x32, 0x0F,          # MUS_CTRL_EVENT
        0x32, 0x77,          # default
        # PITCH (type 2)
        0x20, 0x40,
        # RELEASE on channel 5 (within primaries) and channel 14 (re-mapped to 9)
        0x05, 0x3C,
        0x0E, 0x3C,
        # PLAY without running-volume (buf[1] & 0x80 == 0) — reuses last volume
        0x10, 0x40,
        # MEASURE_END
        0x50,
        # Event with bit-7 delay (multi-byte VLQ): 0x80 sets the loop, then
        # 0x82 (cont) 0x05 (final) → delay = 0x02<<7 | 0x05 = 0x105.
        0x90, 0x40, 0x82, 0x05,
        # TRACK_END
        0x60,
    ])
    seed3 = header(primaries=primaries3, secondaries=secondaries3, instc=instc3,
                   event_bytes_len=len(events3)) + patch_list3 + events3
    _write(os.path.join(root, "seeds/dmxmus/all_events.mus"), seed3)

    dict_path = os.path.join(root, "dictionaries/dmxmus.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "w") as f:
        f.write('# DMX .MUS magic and event-type byte high-nibbles\n')
        f.write('"MUS\\x1A"\n')
        for ev in [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]:
            f.write(f'"\\x{ev:02x}"\n')
            f.write(f'"\\x{0x80 | ev:02x}"\n')
    print(f"  wrote {dict_path}")


# ──────────────────────────────────────────────────
#  mpgv: MPEG-I/II video ES (modules/demux/mpeg/mpgv.c)
# ──────────────────────────────────────────────────
#
# The mpgv module is linked via fuzzing-modules.patch and registered in the
# PLUGINS list, but without a seed corpus directory no
# vlc-demux-dec-libfuzzer-mpgv binary is produced. The seed below has a
# sequence_header_code (0x000001B3) that passes CheckMPEGStartCode in mpgv.c:
# 0xB3 is not in {0xB0, 0xB1, 0xB6} and 0xB3 <= 0xB9, so VLC_SUCCESS is
# returned. The Demux loop then feeds data to the mpegvideo packetizer.
#
# Sequence header structure (ISO/IEC 11172-2 / ISO/IEC 13818-2):
#   start code (4B) | width(12b)/height(12b) | aspect(4b)/framerate(4b) |
#   bitrate(18b)/marker(1b)/vbv_size(10b)/constrained(1b)/load_flags(2b)

MPGV_ES_SEED = bytes([
    # Sequence header: 352x240, 1:1 aspect, 29.97fps, VBR, vbv=0
    0x00, 0x00, 0x01, 0xB3,
    0x16, 0x00, 0xF0,
    0x15,
    0xFF, 0xFF, 0xE0, 0x00,
    # Group of Pictures header: closed GOP, 00:00:00:00
    0x00, 0x00, 0x01, 0xB8,
    0x00, 0x00, 0x01,
    # Picture header: temporal_ref=0, I-frame
    0x00, 0x00, 0x01, 0x00,
    0x00, 0x10, 0xFF, 0xFF,
    # Slice: slice_vertical_position=1, quantiser_scale=1
    0x00, 0x00, 0x01, 0x01,
    0x22, 0x00, 0x00,
])

MPGV_DICT = """# MPEG-1/2 video start codes (ISO/IEC 11172-2 / ISO/IEC 13818-2)
# libFuzzer dictionary format: one token per line, inline comments not allowed.
"\\x00\\x00\\x01\\xB3"
"\\x00\\x00\\x01\\xB7"
"\\x00\\x00\\x01\\xB8"
"\\x00\\x00\\x01\\x00"
"\\x00\\x00\\x01\\xB5"
"\\x00\\x00\\x01\\xB2"
"\\x00\\x00\\x01\\x01"
"\\x00\\x00\\x01\\xAF"
"\\x00\\x00\\x01"
"""


def gen_mpgv(root):
    _write(os.path.join(root, "seeds/mpgv/minimal.mpgv"), MPGV_ES_SEED)
    dict_path = os.path.join(root, "dictionaries/mpgv.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "w") as f:
        f.write(MPGV_DICT)
    print(f"  wrote {dict_path}")


# ──────────────────────────────────────────────────
#  h264 CEA-708 SEI seed (appended to upstream h264 corpus)
# ──────────────────────────────────────────────────
#
# packetizer/hxxx_sei.c extracts SEI user_data_registered_itu_t_t35 payloads
# with country=0xB5, provider=0x0031, fourcc=GA94 + 0x03 marker, and forwards
# them to codec/cc.c which dispatches to CEA708_Decoder_Push in codec/cea708.c
# (0/1205 lines after round 1 — this seed unlocks that decoder).

def _rbsp(payload: bytes) -> bytes:
    """Insert emulation prevention bytes 0x03 after sequences of two 0x00."""
    out = bytearray()
    zeros = 0
    for b in payload:
        if zeros >= 2 and b <= 0x03:
            out.append(0x03)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)


# ──────────────────────────────────────────────────
# CEA-708 DTVCC packet construction
# ──────────────────────────────────────────────────
# modules/codec/cea708.c (~1200 lines, 9.3% in 2026-05-16 coverage report)
# is fed via H.264 SEI user_data_registered_itu_t_t35 → cc_data records
# (3 bytes each, ATSC A/53). Each record:
#   bits 7-3: marker (0x1F), bit 2: valid, bits 1-0: cc_type
#   cc_type 3 = DTVCC packet header (data[2] is first packet byte)
#   cc_type 2 = DTVCC packet data (data[1], data[2] are next 2 bytes)
# The first byte of a packet encodes seq (bits 7-6) and packet_size_code
# (bits 5-0); actual payload size = packet_size_code * 2 - 1 bytes
# (or 127 if code == 0). Inside that payload sit service blocks:
#   byte 0: service_id (bits 7-5), block_size (bits 4-0)
# Service block data is then parsed by CEA708_Decoder which routes C0/G0/
# C1/G1/G2/G3 codes to the dedicated Decode_* functions. The default seed
# in vlc-fuzz-corpus delivers a malformed 1-byte packet, so essentially
# no Decode_C* / Decode_G* function ever runs. This generator fixes that.

def _cea708_service_block(sid: int, payload: bytes) -> bytes:
    assert 1 <= sid <= 6, 'standard service id range; use _cea708_extsb otherwise'
    assert len(payload) <= 0x1F, 'service block size field is 5 bits'
    return bytes([(sid << 5) | (len(payload) & 0x1F)]) + payload


def _cea708_extended_service_block(ext_sid: int, payload: bytes) -> bytes:
    # 2-byte header form: 0xE0 | size, then 0x00 | ext_sid (>=7).
    assert 7 <= ext_sid <= 0x3F
    assert len(payload) <= 0x1F
    return bytes([(0x07 << 5) | (len(payload) & 0x1F),
                  ext_sid & 0x3F]) + payload


def _cea708_define_window(visible: bool, prio: int, anchor_point: int,
                          row_count: int, col_count: int,
                          win_style: int = 1, pen_style: int = 1) -> bytes:
    b0 = (1 if visible else 0) << 5 | 0x18 | (prio & 0x07)  # row/col lock + prio
    b1 = 0x00                                                # relative=0, anchor_v=0
    b2 = 0x00                                                # anchor_h
    b3 = ((anchor_point & 0x0F) << 4) | (row_count & 0x0F)
    b4 = col_count & 0x3F
    b5 = ((win_style & 0x07) << 3) | (pen_style & 0x07)
    return bytes([b0, b1, b2, b3, b4, b5])


def _cea708_set_window_attrs() -> bytes:
    # fill_opacity=2, fill_color=0x05; border_color=0x06, border_type=0;
    # border_type_msb=0, word_wrap=1, print_dir=0, scroll_dir=0, justify=0;
    # effect_speed=0, effect_dir=0, display_effect=0.
    return bytes([0x85, 0x06, 0x40, 0x00])


def _cea708_set_pen_attrs() -> bytes:
    # text_tag=0, offset=0, size=1; italics=0, underline=1, edge_type=2, font=1.
    return bytes([0x01, 0x4A])


def _cea708_set_pen_color() -> bytes:
    # fg op=2 col=0x10; bg op=2 col=0x20; edge col=0x05.
    return bytes([0x90, 0xA0, 0x05])


def _cea708_set_pen_location(row: int, col: int) -> bytes:
    return bytes([row & 0x0F, col & 0x3F])


def _build_cea708_service1() -> bytes:
    """Service block #1: define+show window, set attrs, write G0 + G2
       chars + P16, then ETX to flush.  Fits in a 31-byte service block."""
    out = bytearray()
    out.append(0x98)                                  # DF0 (define window 0)
    out += _cea708_define_window(visible=True, prio=4, anchor_point=4,
                                 row_count=2, col_count=10)
    out.append(0x97); out += _cea708_set_window_attrs()       # SWA
    out.append(0x90); out += _cea708_set_pen_attrs()          # SPA
    out += b'Hi'                                      # G0 chars
    out.append(0x0D)                                  # C0 CR
    out.append(0x10); out.append(0x25)                # C0 EXT1 + G2 ellipsis
    out.append(0x18); out.append(0x4E); out.append(0x6F)  # P16 'N','o'
    out.append(0x91); out += _cea708_set_pen_color()          # SPC
    out.append(0x03)                                  # C0 ETX
    assert len(out) <= 0x1F, f'service1 too large: {len(out)}'
    return bytes(out)


def _build_cea708_service2() -> bytes:
    """Service block #2: C1 window-bitmask commands + delay + reset, plus
       a G1 char (>=0xA0).  ~12 bytes."""
    out = bytearray()
    out.append(0xA1)                  # G1 char (latin '¡')
    out.extend([0x88, 0x01])          # CLW window 0
    out.extend([0x89, 0x01])          # DSW window 0
    out.extend([0x8A, 0x02])          # HDW window 1
    out.extend([0x8B, 0x01])          # TGW window 0
    out.extend([0x8D, 0x05])          # DLY 0.5s
    out.append(0x8E)                  # DLC
    out.append(0x8F)                  # RST
    return bytes(out)


def _build_cea708_service3() -> bytes:
    """Service block: DF7 (define window 7) + CW7 + SPL + chars. Exercises
       the CW7/DF7 endpoints of the CEA708_C1_CWx / DFx range checks."""
    out = bytearray()
    out.append(0x9F)                                  # DF7 (define window 7)
    out += _cea708_define_window(visible=True, prio=2, anchor_point=8,
                                 row_count=4, col_count=20,
                                 win_style=3, pen_style=4)
    out.append(0x87)                                  # CW7
    out.append(0x92); out += _cea708_set_pen_location(1, 2)
    out += b'World'
    out.append(0x03)
    return bytes(out)


def _cea708_pack_packet(service_blocks: list, seq: int = 0):
    """Pack service blocks into a DTVCC packet.
       Returns ``(size_byte, payload_bytes)`` where payload_bytes is what
       ends up in the demuxer's per-packet buffer (h->data) and size_byte
       is the byte placed in data[1] of the header cc_data record."""
    payload = b''.join(service_blocks)
    # The demuxer reads pktsize_code from data[1] & 63 and computes the
    # target size as ``code * 2 - 1`` bytes (or 127 if code==0). Payload
    # length must therefore be odd.
    if len(payload) % 2 == 0:
        payload += bytes([0x00])
    target = len(payload)
    assert 1 <= target <= 127
    code = (target + 1) // 2
    if code == 64:
        code = 0
    size_byte = ((seq & 0x03) << 6) | (code & 0x3F)
    return size_byte, payload


def _cea708_cc_data_records(size_byte: int, payload: bytes) -> bytes:
    """Convert a DTVCC packet (size byte + payload) into cc_data records.
       Header record carries (0xFF, size_byte, payload[0]); subsequent
       data records carry (0xFE, payload[i], payload[i+1])."""
    assert len(payload) >= 1
    assert len(payload) % 2 == 1, 'payload length must be odd (pad NUL upstream)'
    out = bytearray([0xFF, size_byte, payload[0]])
    i = 1
    while i < len(payload):
        out.extend([0xFE, payload[i], payload[i + 1]])
        i += 2
    return bytes(out)


def _cea708_cc_data_payload(packets: list) -> bytes:
    """Concatenate cc_data records for several DTVCC packets plus a
       trailing NTSC field-1 record to also exercise the CEA-608 path.
       ``packets`` is a list of ``(size_byte, payload_bytes)`` tuples."""
    cc_data = b''.join(_cea708_cc_data_records(s, p) for s, p in packets)
    cc_data += bytes([0xFC, 0x41, 0x80])               # NTSC F1 'A'
    cc_count = len(cc_data) // 3
    assert cc_count <= 0x1F, f'cc_count {cc_count} too large'
    return bytes([0xC0 | (cc_count & 0x1F), 0xFF]) + cc_data


def cea708_h264_payload() -> bytes:
    """Returns a raw H.264 ES byte-stream carrying an SPS/PPS/SEI(CC)/IDR
       sequence.  Used both as a stand-alone ``.264`` seed (gen_h264) and
       wrapped in MPEG-TS PES below for the cea708_video.ts seed."""
    return _build_h264_cea708_seed()


def _cea708_sei_nal(cc_packets: list) -> bytes:
    """Wrap one or more DTVCC packets in an H.264 SEI user_data_registered_
       itu_t_t35 NAL.  cc_count is capped at 31 so very long sequences must
       be split across multiple SEIs."""
    cc_data = _cea708_cc_data_payload(cc_packets)
    t35 = (bytes([0xB5, 0x00, 0x31]) + b'GA94'
           + bytes([0x03]) + cc_data + bytes([0xFF]))
    sei_payload = bytes([0x04, len(t35) & 0xFF]) + t35 + bytes([0x80])
    return bytes([0x06]) + _rbsp(sei_payload)


def _build_h264_cea708_seed() -> bytes:
    # Each SEI fits ≤ 31 cc_data triplets; split rich packets across two.
    sei1 = _cea708_sei_nal([
        _cea708_pack_packet([
            _cea708_service_block(1, _build_cea708_service1()),
            _cea708_service_block(2, _build_cea708_service2()),
        ], seq=0),
    ])
    sei2 = _cea708_sei_nal([
        _cea708_pack_packet([
            _cea708_service_block(3, _build_cea708_service3()),
            _cea708_extended_service_block(0x10, b'\x80\x83\x03'),
        ], seq=1),
    ])

    sps = bytes([0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8])
    pps = bytes([0x68, 0xCE, 0x38, 0x80])
    idr = bytes([0x65, 0x88, 0x84, 0x00, 0x33, 0xFF])

    sc = b'\x00\x00\x00\x01'
    return sc + sps + sc + pps + sc + sei1 + sc + sei2 + sc + idr


def gen_h264(root):
    # Appended to the upstream h264 corpus shipped in vlc-fuzz-corpus.
    _write(os.path.join(root, "seeds/h264/cea708_sei.264"),
           _build_h264_cea708_seed())


# ──────────────────────────────────────────────────
#  TTA (True Audio) seeds (modules/demux/tta.c)
# ──────────────────────────────────────────────────
#
# The vlc-fuzz-corpus tree has no seeds/tta directory, so the
# vlc-demux-dec-libfuzzer-tta target starts every campaign with an empty
# corpus and the TTA1 magic check at modules/demux/tta.c:96 fails on every
# random byte. Public report (2026-05-13): 21/161 lines (13.0%).
#
# tta.c Open() requires:
#   off  0  "TTA1"          (4)
#   off  4  AudioFormat     (2  little-endian)
#   off  6  NumChannels     (2  little-endian)
#   off  8  BitsPerSample   (2  little-endian)
#   off 10  SampleRate      (4  little-endian)  must be > 0 and <= 1<<20
#   off 14  DataLength      (4  little-endian)
#   off 18  HeaderCRC32     (4  little-endian) — not validated by demuxer
# Then a per-frame seektable (totalframes * 4 bytes) and a 4-byte trailing
# CRC; Demux() reads seektable[i] bytes per frame and pushes them to es_out.

def _tta_seed(rate, channels, bps, datalen, frame_bytes_list):
    header = (b"TTA1"
              + struct.pack("<H", 1)
              + struct.pack("<H", channels)
              + struct.pack("<H", bps)
              + struct.pack("<I", rate)
              + struct.pack("<I", datalen)
              + struct.pack("<I", 0))
    seektable = b"".join(struct.pack("<I", n) for n in frame_bytes_list)
    seektable_crc = struct.pack("<I", 0)
    payload = b"".join(b"\x00" * n for n in frame_bytes_list)
    return header + seektable + seektable_crc + payload


def gen_tta(root):
    _write(os.path.join(root, "seeds/tta/minimal.tta"),
           _tta_seed(rate=44100, channels=2, bps=16,
                     datalen=88200, frame_bytes_list=(50,)))
    _write(os.path.join(root, "seeds/tta/multi_frame.tta"),
           _tta_seed(rate=22050, channels=1, bps=16,
                     datalen=22050 * 3, frame_bytes_list=(40, 30, 35)))
    _write(os.path.join(root, "seeds/tta/mono8.tta"),
           _tta_seed(rate=8000, channels=1, bps=8,
                     datalen=8000, frame_bytes_list=(20, 25)))

    dict_path = os.path.join(root, "dictionaries/tta.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "w") as f:
        f.write('# TTA (True Audio) lossless audio magic + sample rates\n')
        f.write('"TTA1"\n')
        f.write('"\\x01\\x00"\n')
        f.write('"\\x44\\xAC\\x00\\x00"\n')
        f.write('"\\x22\\x56\\x00\\x00"\n')
        f.write('"\\x40\\x1F\\x00\\x00"\n')
    print(f"  wrote {dict_path}")


# ──────────────────────────────────────────────────
#  CAF (Apple Core Audio File Format) seeds — extend coverage of
#  modules/demux/caf.c. Upstream vlc-fuzz-corpus seeds/caf/* exercise the
#  PCM/LPCM happy path plus a minimal AAC-with-kuki and a stub pakt. They do
#  NOT reach:
#    * ProcessALACCookie (both 24- and 36-byte kuki shapes)
#    * ProcessAACCookie branches behind ES_Descriptor flag bits 0x80/0x40/0x20
#    * ReadKukiChunk's generic non-ALAC/non-AAC branch (i_codec != 0)
#    * Demux()'s VBR/packet-table branch + FrameSpanAddDescription's two
#      var-len-integer parsing paths (bytes-only and bytes+samples)
#  Each seed below is the smallest synthetic CAF that drives one of those
#  paths end-to-end through Open() and at least one Demux() iteration.
# ──────────────────────────────────────────────────
def _caf_varint(n):
    """CAF/ESDS variable-length integer (7 bits/byte, MSB=continuation)."""
    if n == 0:
        return b'\x00'
    out = []
    while n:
        out.append(n & 0x7f)
        n >>= 7
    out.reverse()
    return bytes([b | 0x80 for b in out[:-1]] + [out[-1]])


def _caf_chunk(fourcc, body):
    assert len(fourcc) == 4
    return fourcc + struct.pack('>q', len(body)) + body


def _caf_desc(rate, fmt_id, fmt_flags=0,
              bytes_per_packet=0, frames_per_packet=0,
              channels=2, bits=16):
    assert len(fmt_id) == 4
    return (struct.pack('>d', float(rate)) + fmt_id +
            struct.pack('>IIIII', fmt_flags, bytes_per_packet,
                        frames_per_packet, channels, bits))


_CAF_HEADER = b'caff' + struct.pack('>HH', 1, 0)


def _caf_aac_esds_basic():
    """24-byte AAC ESDS magic cookie, no optional flags — same shape as the
    upstream aac_with_kuki.caf seed. ProcessAACCookie walks all the mandatory
    descriptors and extracts the 2-byte AudioSpecificConfig."""
    return (b'\x03\x16'                  # ES_DESCR_TAG, len=22
            b'\x00\x01'                  # ES_ID
            b'\x00'                      # flags=0 (no 0x80/0x40/0x20)
            b'\x04\x11'                  # DEC_CONFIG_DESCR_TAG, len=17
            b'\x40\x15\x00\x00\x00\x00\x01\xf4\x00\x00\x01\xf4\x00'
            b'\x05\x02'                  # DEC_SPEC_INFO_TAG, len=2
            b'\x11\x90')                 # AudioSpecificConfig (AAC LC, 44.1k stereo)


def _caf_aac_esds_full_flags():
    """ESDS exercising the dependence (0x80), URL (0x40) and OCR (0x20) bits.
    These three branches in ProcessAACCookie are unreached by upstream seeds."""
    return (b'\x03\x1b'                  # ES_DESCR_TAG, len=27
            b'\x00\x01'                  # ES_ID
            b'\xe0'                      # flags=0x80|0x40|0x20
            b'\x00\x00'                  # 2 bytes dependence (0x80)
            b'\x00'                      # URL length=0 (0x40)
            b'\x00\x00'                  # 2 bytes OCR (0x20)
            b'\x04\x0d'                  # DEC_CONFIG_DESCR_TAG, len=13
            b'\x40\x15\x00\x00\x00\x00\x01\xf4\x00\x00\x01\xf4\x00'
            b'\x05\x02'
            b'\x11\x90')


def _caf_alac_cookie24():
    """24-byte ALAC magic cookie (the "new" shape libavformat documents).
    ProcessALACCookie expands this to 36 bytes by prefixing size+"alac"+ver."""
    return struct.pack('>I', 4096) + bytes([
        0,      # compatibleVersion
        16,     # bitDepth
        40,     # pb
        14,     # mb
        10,     # kb
        2,      # numChannels
    ]) + struct.pack('>H', 255) + struct.pack('>III', 0, 0, 44100)


def _caf_alac_cookie36():
    """36-byte ALAC magic cookie (size + 'alac' + version + 24-byte config)."""
    return (struct.pack('>I', 36) + b'alac' + struct.pack('>I', 0)
            + _caf_alac_cookie24())


def _caf_build(chunks):
    return _CAF_HEADER + b''.join(chunks)


def gen_caf(root):
    # 1) VBR-style AAC with full packet table: bytes_per_packet=0 AND
    #    frames_per_packet=0 forces NeedsPacketTable=true and makes
    #    FrameSpanAddDescription parse a var-len integer for *both* the byte
    #    count and the sample count of each packet.
    aac_kuki = _caf_aac_esds_basic()
    descs = []
    for nbytes, nsamples in [(50, 1024), (30, 1024), (20, 1024)]:
        descs.append(_caf_varint(nbytes) + _caf_varint(nsamples))
    pakt_body = (struct.pack('>q', 3)        # num_packets
                 + struct.pack('>q', 3072)   # valid_frames
                 + struct.pack('>i', 0)      # priming
                 + struct.pack('>i', 0)      # remainder
                 + b''.join(descs))
    data_payload = bytes(50 + 30 + 20)
    vbr_caf = _caf_build([
        _caf_chunk(b'desc', _caf_desc(44100, b'aac ', fmt_flags=2,
                                      bytes_per_packet=0, frames_per_packet=0,
                                      channels=2, bits=0)),
        _caf_chunk(b'kuki', aac_kuki),
        _caf_chunk(b'pakt', pakt_body),
        _caf_chunk(b'data', struct.pack('>I', 0) + data_payload),
    ])
    _write(os.path.join(root, 'seeds/caf/vbr_aac_full_pakt.caf'), vbr_caf)

    # 2) ALAC with 24-byte cookie. desc has bytes_per_packet=0 AND
    #    frames_per_packet=4096, so Demux() takes the packet-table branch but
    #    FrameSpanAddDescription's *bytes-only* path runs (frame_length is
    #    known, byte count comes from a var-len integer).
    alac24_descs = b''.join(_caf_varint(n) for n in (200, 180, 160))
    alac24_pakt = (struct.pack('>q', 3)
                   + struct.pack('>q', 3 * 4096)
                   + struct.pack('>i', 0) + struct.pack('>i', 0)
                   + alac24_descs)
    alac24 = _caf_build([
        _caf_chunk(b'desc', _caf_desc(44100, b'alac',
                                      bytes_per_packet=0,
                                      frames_per_packet=4096,
                                      channels=2, bits=16)),
        _caf_chunk(b'kuki', _caf_alac_cookie24()),
        _caf_chunk(b'pakt', alac24_pakt),
        _caf_chunk(b'data', struct.pack('>I', 0) + bytes(200 + 180 + 160)),
    ])
    _write(os.path.join(root, 'seeds/caf/alac_kuki24.caf'), alac24)

    # 3) ALAC with 36-byte cookie — same shape, hits the direct memcpy path
    #    of ProcessALACCookie instead of the size-prefix expansion path.
    alac36 = _caf_build([
        _caf_chunk(b'desc', _caf_desc(48000, b'alac',
                                      bytes_per_packet=0,
                                      frames_per_packet=4096,
                                      channels=2, bits=24)),
        _caf_chunk(b'kuki', _caf_alac_cookie36()),
        _caf_chunk(b'pakt', alac24_pakt),
        _caf_chunk(b'data', struct.pack('>I', 0) + bytes(200 + 180 + 160)),
    ])
    _write(os.path.join(root, 'seeds/caf/alac_kuki36.caf'), alac36)

    # 4) AAC with ESDS dependence/URL/OCR bits set — drives the three
    #    optional-block branches at lines ~630-645 of caf.c.
    aac_full = _caf_build([
        _caf_chunk(b'desc', _caf_desc(44100, b'aac ', fmt_flags=2,
                                      bytes_per_packet=240,
                                      frames_per_packet=1024,
                                      channels=2, bits=0)),
        _caf_chunk(b'kuki', _caf_aac_esds_full_flags()),
        _caf_chunk(b'data', struct.pack('>I', 0) + bytes(240 * 2)),
    ])
    _write(os.path.join(root, 'seeds/caf/aac_full_esds_flags.caf'), aac_full)

    # 5) lpcm + kuki — non-ALAC, non-AAC codec with a non-zero i_codec, so
    #    ReadKukiChunk takes the generic else branch that copies the cookie
    #    verbatim into fmt.p_extra.
    lpcm_kuki = _caf_build([
        _caf_chunk(b'desc', _caf_desc(44100, b'lpcm',
                                      fmt_flags=0x0c,   # signed/be
                                      bytes_per_packet=4,
                                      frames_per_packet=1,
                                      channels=2, bits=16)),
        _caf_chunk(b'kuki', b'GENERICCOOKIE' + bytes(8)),
        _caf_chunk(b'data', struct.pack('>I', 0) + bytes(64)),
    ])
    _write(os.path.join(root, 'seeds/caf/lpcm_with_kuki.caf'), lpcm_kuki)


# ──────────────────────────────────────────────────
#  WAV / AIFF / CAF seeds for araw.c (raw-audio decoder) — extend coverage of
#  modules/codec/araw.c. The native araw module wins decoder selection over
#  avcodec (capability 100 vs 70) for the listed fourccs, so blocks really do
#  flow into the per-format Decode* helpers. Upstream wav/aiff corpora only
#  cover S16L (16-bit PCM), S24L (24-bit PCM), F32L (IEEE float 32) plus
#  big-endian S24B and S16B via AIFF. That leaves these araw branches dead:
#    * FL64  / F64L            ← 64-bit IEEE float
#    * S32N  (= S32L on LE)    ← 32-bit signed PCM
#    * extensible-PCM dispatch in wav.c that consumes sf_tag_to_fourcc paths
#  Each seed below is a minimal, well-formed container that resolves to one
#  of these dead codec branches via vlc_fourcc_GetCodecAudio.
# ──────────────────────────────────────────────────
def _riff_chunk(fourcc, body):
    assert len(fourcc) == 4
    return fourcc + struct.pack('<I', len(body)) + body


def _wav_fmt_basic(fmt_tag, channels, rate, bits, block_align=None):
    if block_align is None:
        block_align = channels * (bits // 8)
    avg_bps = rate * block_align
    return struct.pack('<HHIIHH', fmt_tag, channels, rate, avg_bps,
                       block_align, bits)


def _wav_fmt_extensible(channels, rate, bits, channel_mask, subformat_guid):
    assert len(subformat_guid) == 16
    block_align = channels * (bits // 8)
    avg_bps = rate * block_align
    cb_size = 22                          # remainder after WAVEFORMATEX
    # WAVEFORMATEX(16) + cbSize(2) + wValidBitsPerSample(2) + dwChannelMask(4) + GUID(16)
    return (struct.pack('<HHIIHH', 0xFFFE, channels, rate, avg_bps,
                        block_align, bits)
            + struct.pack('<HHI', cb_size, bits, channel_mask)
            + subformat_guid)


def _wav_file(fmt_body, data_body):
    fmt_chunk = _riff_chunk(b'fmt ', fmt_body)
    data_chunk = _riff_chunk(b'data', data_body)
    payload = b'WAVE' + fmt_chunk + data_chunk
    return b'RIFF' + struct.pack('<I', len(payload)) + payload


# KSDATAFORMAT_SUBTYPE_PCM / IEEE_FLOAT GUIDs (Microsoft).
_GUID_PCM        = bytes.fromhex('0100000000001000800000aa00389b71')
_GUID_IEEE_FLOAT = bytes.fromhex('0300000000001000800000aa00389b71')


def gen_araw(root):
    # 1) WAVE_FORMAT_IEEE_FLOAT, 64-bit, stereo. wav.c maps this to fourcc
    #    'aflt'; vlc_fourcc_GetCodecAudio('aflt', 64) → VLC_CODEC_FL64
    #    → araw.c case VLC_CODEC_FL64 (line 137) which is currently 0%.
    f64_data = bytes(8 * 2 * 16)          # 16 stereo float64 frames
    _write(os.path.join(root, 'seeds/wav/ieee_float64_stereo.wav'),
           _wav_file(_wav_fmt_basic(0x0003, channels=2, rate=44100, bits=64),
                     f64_data))

    # 2) WAVE_FORMAT_PCM, 32-bit, stereo. wav.c maps PCM to 'araw';
    #    vlc_fourcc_GetCodecAudio('araw', 32) → VLC_CODEC_S32L → on LE the
    #    araw case VLC_CODEC_S32N (line 168) fires. Currently 0%.
    s32_data = bytes(4 * 2 * 64)
    _write(os.path.join(root, 'seeds/wav/pcm_32bit_stereo.wav'),
           _wav_file(_wav_fmt_basic(0x0001, channels=2, rate=48000, bits=32),
                     s32_data))

    # 3) WAVE_FORMAT_EXTENSIBLE with KSDATAFORMAT_SUBTYPE_PCM and 32-bit
    #    samples. Exercises the GUID-resolution branch in wav.c
    #    (sf_tag_to_fourcc) on top of the same araw S32N codepath. This is
    #    additionally interesting because EXTENSIBLE wires up the channel
    #    layout / chans_to_reorder branch that plain WAVE_FORMAT_PCM skips.
    _write(os.path.join(root, 'seeds/wav/extensible_pcm32_quad.wav'),
           _wav_file(_wav_fmt_extensible(channels=4, rate=48000, bits=32,
                                         channel_mask=0x33,  # FL FR BL BR
                                         subformat_guid=_GUID_PCM),
                     bytes(4 * 4 * 32)))

    # 4) WAVE_FORMAT_EXTENSIBLE with KSDATAFORMAT_SUBTYPE_IEEE_FLOAT and
    #    64-bit samples — drives the same EXTENSIBLE/GUID code in wav.c but
    #    resolves to FL64 in araw, complementing seed (1).
    _write(os.path.join(root, 'seeds/wav/extensible_float64_stereo.wav'),
           _wav_file(_wav_fmt_extensible(channels=2, rate=96000, bits=64,
                                         channel_mask=0x3,
                                         subformat_guid=_GUID_IEEE_FLOAT),
                     bytes(8 * 2 * 16)))

    # 5) WAV PCM 8-channel surround at 32-bit. Stresses both the channel-mask
    #    fan-out in wav.c (>2 channels triggers the pi_default_channels
    #    fill-in loop, which is mostly unhit) and the per-frame size math in
    #    araw's main Decode entry. Block-align is 8 channels × 4 bytes = 32.
    _write(os.path.join(root, 'seeds/wav/pcm_32bit_8ch.wav'),
           _wav_file(_wav_fmt_extensible(channels=8, rate=48000, bits=32,
                                         channel_mask=0x63F,
                                         subformat_guid=_GUID_PCM),
                     bytes(32 * 16)))


# ──────────────────────────────────────────────────
#  Extended HEIF seeds — transform & decoder-config properties
# ──────────────────────────────────────────────────
#
# heif_basic/avif_basic/heic_grid (above) exercise the ipco/ipma/iloc
# walking paths but never the property branches at heif.c:371-451 (hvcC,
# avcC, av1C, irot, clap, colr, clli, mdcv). These extra seeds attach a
# realistic hvcC/av1C config + each transform property in turn so the
# associated SetupES paths run.

def hvcC_box() -> bytes:
    body = bytes([
        0x01,            # configurationVersion
        0x42, 0xC0, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0,
        0x00, 0xFC, 0xFD, 0xF8, 0xF8, 0x00, 0x00, 0x0F,
        0x00,
    ])
    return box(b'hvcC', body)


def av1C_box() -> bytes:
    body = bytes([0x81, 0x05, 0x0C, 0x00])
    return box(b'av1C', body)


def irot_box(rot_idx: int) -> bytes:
    return box(b'irot', bytes([rot_idx & 0x03]))


def imir_box(axis: int) -> bytes:
    return box(b'imir', bytes([axis & 0x01]))


def colr_nclx_box() -> bytes:
    body = b'nclx' + struct.pack('>HHHB', 1, 13, 1, 0x80)
    return box(b'colr', body)


def clap_box(w_n, w_d, h_n, h_d, x_n, x_d, y_n, y_d) -> bytes:
    body = struct.pack('>iiiiiiii', w_n, w_d, h_n, h_d, x_n, x_d, y_n, y_d)
    return box(b'clap', body)


def seed_heic_with_hvcC() -> bytes:
    img_data = bytes([0x00, 0x00, 0x00, 0x02, 0x40, 0x01])
    iinf_box = iinf([infe(1, b'hvc1', b'IMG\x00')])
    pitm_box = pitm(1)
    ipco_box = ipco([
        ispe(64, 48),
        hvcC_box(),
        pixi([8, 8, 8]),
        colr_nclx_box(),
    ])
    ipma_box = ipma([(1, [1, 2, 3, 4])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(img_data))], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iprp_box])
    ftyp_box = ftyp(b'heic', [b'mif1', b'heic'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(img_data))], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iprp_box])
    mdat_box = box(b'mdat', img_data)
    return ftyp_box + meta_box + mdat_box


def seed_heic_irot() -> bytes:
    img_data = bytes([0x00, 0x00, 0x00, 0x02, 0x40, 0x01])
    iinf_box = iinf([infe(1, b'hvc1', b'IMG\x00')])
    pitm_box = pitm(1)
    ipco_box = ipco([
        ispe(32, 32),
        hvcC_box(),
        irot_box(1),       # 90° CCW
        imir_box(1),
        clap_box(16, 1, 16, 1, 8, 1, 8, 1),
    ])
    ipma_box = ipma([(1, [1, 2, 3, 4, 5])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(img_data))], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iprp_box])
    ftyp_box = ftyp(b'heic', [b'mif1', b'heic'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(img_data))], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iprp_box])
    mdat_box = box(b'mdat', img_data)
    return ftyp_box + meta_box + mdat_box


def seed_avif_with_av1C() -> bytes:
    img_data = bytes([0x12, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00])
    iinf_box = iinf([infe(1, b'av01', b'AV1\x00')])
    pitm_box = pitm(1)
    ipco_box = ipco([
        ispe(16, 16),
        av1C_box(),
        pixi([8, 8, 8]),
        colr_nclx_box(),
        irot_box(2),
    ])
    ipma_box = ipma([(1, [1, 2, 3, 4, 5])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(img_data))], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iprp_box])
    ftyp_box = ftyp(b'avif', [b'mif1', b'avif'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(img_data))], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iprp_box])
    mdat_box = box(b'mdat', img_data)
    return ftyp_box + meta_box + mdat_box


def iref_thmb(from_id: int, to_id: int) -> bytes:
    body = struct.pack('>HH', from_id, 1) + struct.pack('>H', to_id)
    return fullbox(b'iref', 0, 0, box(b'thmb', body))


def seed_heic_thumb() -> bytes:
    main_data = bytes([0x00, 0x00, 0x00, 0x02, 0x40, 0x01])
    thumb_data = bytes([0x00, 0x00, 0x00, 0x02, 0x40, 0x02])
    iinf_box = iinf([
        infe(1, b'hvc1', b'MAIN\x00'),
        infe(2, b'hvc1', b'THMB\x00'),
    ])
    pitm_box = pitm(1)
    iref_box = iref_thmb(2, 1)
    ipco_box = ipco([
        ispe(64, 48),
        hvcC_box(),
        ispe(16, 12),
    ])
    ipma_box = ipma([(1, [1, 2]), (2, [3, 2])])
    iprp_box = iprp(ipco_box, ipma_box)
    placeholder = iloc([(1, len(main_data)), (2, len(thumb_data))], 0)
    meta_box = meta([pitm_box, iinf_box, placeholder, iref_box, iprp_box])
    ftyp_box = ftyp(b'heic', [b'mif1', b'heic'])
    mdat_off = len(ftyp_box) + len(meta_box) + 8
    iloc_box = iloc([(1, len(main_data)), (2, len(thumb_data))], mdat_off)
    meta_box = meta([pitm_box, iinf_box, iloc_box, iref_box, iprp_box])
    mdat_box = box(b'mdat', main_data + thumb_data)
    return ftyp_box + meta_box + mdat_box


HEIF_EXTRA_SEEDS = {
    'heic_hvcC.heic':  seed_heic_with_hvcC,
    'heic_irot.heic':  seed_heic_irot,
    'avif_av1C.avif':  seed_avif_with_av1C,
    'heic_thumb.heic': seed_heic_thumb,
}


def gen_heif_extra(root):
    seed_dir = os.path.join(root, 'seeds', 'heif')
    os.makedirs(seed_dir, exist_ok=True)
    for filename, gen in HEIF_EXTRA_SEEDS.items():
        data = gen()
        with open(os.path.join(seed_dir, filename), 'wb') as f:
            f.write(data)
        print(f'  seeds/heif/{filename}: {len(data)} bytes')


# ──────────────────────────────────────────────────
#  Ogg seeds — Speex header + data packets (codec/speex.c)
# ──────────────────────────────────────────────────
#
# Round 2 deferred this with "Constructing a structurally valid Ogg page
# requires CRC-32/Ogg over the entire page with the CRC field zeroed;
# doable in Python but high-effort for what would be a single seed."
# Round 3 implements the CRC + page builder and adds a multi-page Speex
# stream so OpenDecoder + ProcessInitialHeader + DecodeBlock are exercised.

_OGG_CRC_TABLE = None


def _ogg_crc_table():
    global _OGG_CRC_TABLE
    if _OGG_CRC_TABLE is None:
        tbl = [0] * 256
        for i in range(256):
            r = i << 24
            for _ in range(8):
                r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (r & 0x80000000) else ((r << 1) & 0xFFFFFFFF)
            tbl[i] = r
        _OGG_CRC_TABLE = tbl
    return _OGG_CRC_TABLE


def ogg_crc32(data: bytes) -> int:
    tbl = _ogg_crc_table()
    r = 0
    for b in data:
        r = ((r << 8) ^ tbl[((r >> 24) ^ b) & 0xFF]) & 0xFFFFFFFF
    return r


def ogg_page(packets, *, serial: int, page_seq: int, granule: int = 0,
             bos: bool = False, eos: bool = False,
             continued: bool = False) -> bytes:
    """Pack one or more whole packets into a single Ogg page.

    Each entry in `packets` is the raw packet bytes; segment lacing values
    are computed as 0xFF * (len // 255) followed by (len % 255).  Caller is
    responsible for keeping the total segment count ≤ 255.
    """
    segs = bytearray()
    body = bytearray()
    for pkt in packets:
        n = len(pkt)
        while n >= 255:
            segs.append(255)
            n -= 255
        segs.append(n)
        body.extend(pkt)
    assert len(segs) <= 255, "too many segments for one Ogg page"
    htype = (0x01 if continued else 0) | (0x02 if bos else 0) | (0x04 if eos else 0)
    header = (b'OggS'
              + bytes([0, htype])
              + struct.pack('<q', granule)
              + struct.pack('<I', serial)
              + struct.pack('<I', page_seq)
              + struct.pack('<I', 0)   # CRC placeholder
              + bytes([len(segs)])
              + bytes(segs))
    page = bytes(header) + bytes(body)
    crc = ogg_crc32(page)
    return page[:22] + struct.pack('<I', crc) + page[26:]


def _speex_header_packet(rate: int = 16000, channels: int = 1,
                         mode: int = 1, frames_per_packet: int = 1,
                         frame_size: int = 320, nb_packets: int = 0xFFFFFFFF) -> bytes:
    """Build the 80-byte Speex BOS header.  The reference layout (from
    libspeex/speex_header.c) is:
      char speex_string[8]       = "Speex   "
      char speex_version[20]
      int  speex_version_id
      int  header_size  = 80
      int  rate
      int  mode         = 0 (NB) / 1 (WB) / 2 (UWB)
      int  mode_bitstream_version
      int  nb_channels
      int  bitrate      = -1
      int  frame_size
      int  vbr
      int  frames_per_packet
      int  extra_headers
      int  reserved1
      int  reserved2
    """
    speex_string = b'Speex   '
    version = b'speex-1.2.0'.ljust(20, b'\x00')
    return (speex_string
            + version
            + struct.pack('<I', 1)        # speex_version_id
            + struct.pack('<I', 80)       # header_size
            + struct.pack('<I', rate)
            + struct.pack('<I', mode)
            + struct.pack('<I', 4)        # mode_bitstream_version (libspeex 1.2)
            + struct.pack('<I', channels)
            + struct.pack('<i', -1)       # bitrate
            + struct.pack('<I', frame_size)
            + struct.pack('<I', 0)        # vbr
            + struct.pack('<I', frames_per_packet)
            + struct.pack('<I', 0)        # extra_headers
            + struct.pack('<I', 0)        # reserved1
            + struct.pack('<I', 0))       # reserved2


def _speex_comment_packet() -> bytes:
    vendor = b'vlc-fuzz-corpus'
    return (struct.pack('<I', len(vendor)) + vendor + struct.pack('<I', 0))


def seed_speex_full() -> bytes:
    """Multi-page Speex stream: BOS header + comment + several data packets
    + EOS.  The data packets are deliberately small frame-sized blobs; the
    speex decoder will reject them as malformed frames but the rejection
    path still drains through speex_decode_int / cleanup which is far more
    code than just the OpenDecoder + ProcessInitialHeader hot-path the
    existing single-page seed exercises."""
    serial = 0xC0FFEE01
    pages = [
        ogg_page([_speex_header_packet(rate=16000, mode=1, frame_size=320,
                                       frames_per_packet=1)],
                 serial=serial, page_seq=0, granule=0, bos=True),
        ogg_page([_speex_comment_packet()],
                 serial=serial, page_seq=1, granule=0),
    ]
    # Several short audio packets — random-ish bit patterns that exercise
    # the frame-decode error paths in libspeex/nb_celp.c without crashing.
    frames = [
        bytes.fromhex('36ff83e00018'),
        bytes.fromhex('36ff83e00018' '24008000'),
        bytes([0x80, 0x00] * 8),
        bytes([0x55] * 38),
        bytes([0xAA] * 38),
        bytes.fromhex('1e0040201008'),
    ]
    seq = 2
    granule = 320
    for i, f in enumerate(frames):
        pages.append(ogg_page([f], serial=serial, page_seq=seq,
                              granule=granule,
                              eos=(i == len(frames) - 1)))
        seq += 1
        granule += 320
    return b''.join(pages)


def seed_speex_8khz_nb() -> bytes:
    """Narrow-band variant: drives the mode=0 branch in CreateDefaultHeader
    and ProcessInitialHeader."""
    serial = 0xC0FFEE02
    pages = [
        ogg_page([_speex_header_packet(rate=8000, mode=0, frame_size=160,
                                       frames_per_packet=2, channels=1)],
                 serial=serial, page_seq=0, granule=0, bos=True),
        ogg_page([_speex_comment_packet()],
                 serial=serial, page_seq=1, granule=0),
        ogg_page([bytes.fromhex('36ff83e000183600')],
                 serial=serial, page_seq=2, granule=160),
        ogg_page([bytes([0x9F] * 24)],
                 serial=serial, page_seq=3, granule=320, eos=True),
    ]
    return b''.join(pages)


def seed_speex_uwb_stereo() -> bytes:
    """Ultra-wide-band 32 kHz stereo — stereo path adds an inband stereo
    flag-handling branch in libspeex; 2-channel header drives
    ProcessHeader's channel-clamp / fmt_out.audio.i_channels=2 path."""
    serial = 0xC0FFEE03
    pages = [
        ogg_page([_speex_header_packet(rate=32000, mode=2, frame_size=640,
                                       frames_per_packet=1, channels=2)],
                 serial=serial, page_seq=0, granule=0, bos=True),
        ogg_page([_speex_comment_packet()],
                 serial=serial, page_seq=1, granule=0),
        ogg_page([bytes([0x77] * 80)],
                 serial=serial, page_seq=2, granule=640),
        ogg_page([bytes([0x33] * 80)],
                 serial=serial, page_seq=3, granule=1280, eos=True),
    ]
    return b''.join(pages)


def gen_ogg(root):
    out = os.path.join(root, 'seeds', 'ogg')
    os.makedirs(out, exist_ok=True)
    _write(os.path.join(out, 'speex_full.ogg'), seed_speex_full())
    _write(os.path.join(out, 'speex_nb.ogg'), seed_speex_8khz_nb())
    _write(os.path.join(out, 'speex_uwb_stereo.ogg'), seed_speex_uwb_stereo())


# ──────────────────────────────────────────────────
#  MKV seed — Matroska with DVD chapter codec commands
# ──────────────────────────────────────────────────
#
# modules/demux/mkv/chapter_command_dvd.cpp (~700 lines, 0 % in
# 2026-05-16 coverage report).  The native upstream seeds carry plain
# chapters with no ChapterProcess, so dvd_chapter_codec_c is never
# instantiated and its Enter / Interpret entry-points never run.
#
# When matroska_segment_c::ParseChapterAtom encounters a ChapterProcess
# with ChapProcessCodecID == 1 it instantiates dvd_chapter_codec_c and
# routes each ChapterProcessCommand into its enter/during/leave bucket
# (see chapter_command.cpp::AddCommand for the routing).  As soon as the
# demuxer starts streaming (virtual_segment_c::UpdateCurrentToChapter)
# the current chapter's Enter() is invoked, which iterates the
# enter-commands and calls dvd_command_interpretor_c::Interpret on every
# 8-byte sub-command — that's the big function we need to exercise.

def _mkv_vint(value: int) -> bytes:
    """Encode an EBML variable-length size."""
    if value < (1 << 7) - 1:
        return bytes([0x80 | value])
    if value < (1 << 14) - 1:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    if value < (1 << 21) - 1:
        return bytes([0x20 | (value >> 16), (value >> 8) & 0xFF, value & 0xFF])
    if value < (1 << 28) - 1:
        return bytes([0x10 | (value >> 24), (value >> 16) & 0xFF,
                      (value >> 8) & 0xFF, value & 0xFF])
    raise ValueError(f'vint too large: {value}')


def _mkv_id(id_value: int) -> bytes:
    """Encode an element ID as the documented big-endian byte sequence."""
    if id_value <= 0xFF:
        return bytes([id_value])
    if id_value <= 0xFFFF:
        return id_value.to_bytes(2, 'big')
    if id_value <= 0xFFFFFF:
        return id_value.to_bytes(3, 'big')
    return id_value.to_bytes(4, 'big')


def _mkv_elem(elem_id: int, payload: bytes) -> bytes:
    return _mkv_id(elem_id) + _mkv_vint(len(payload)) + payload


def _mkv_uint(elem_id: int, value: int) -> bytes:
    # 1-byte for simplicity unless larger needed.
    nbytes = max(1, (value.bit_length() + 7) // 8)
    data = value.to_bytes(nbytes, 'big')
    return _mkv_elem(elem_id, data)


def _mkv_str(elem_id: int, text: bytes) -> bytes:
    return _mkv_elem(elem_id, text)


def _mkv_bin(elem_id: int, data: bytes) -> bytes:
    return _mkv_elem(elem_id, data)


# Matroska element IDs we use:
_MKV_EBML            = 0x1A45DFA3
_MKV_EBML_VERSION    = 0x4286
_MKV_EBML_READVER    = 0x42F7
_MKV_DOCTYPE         = 0x4282
_MKV_DOCTYPE_VER     = 0x4287
_MKV_DOCTYPE_RDVER   = 0x4285

_MKV_SEGMENT         = 0x18538067
_MKV_INFO            = 0x1549A966
_MKV_TIMECODE_SCALE  = 0x2AD7B1
_MKV_DURATION        = 0x4489
_MKV_MUXAPP          = 0x4D80
_MKV_WRITEAPP        = 0x5741

_MKV_TRACKS          = 0x1654AE6B
_MKV_TRACK_ENTRY     = 0xAE
_MKV_TRACK_NUMBER    = 0xD7
_MKV_TRACK_UID       = 0x73C5
_MKV_TRACK_TYPE      = 0x83
_MKV_CODEC_ID        = 0x86
_MKV_FLAG_LACING     = 0x9C

_MKV_CHAPTERS        = 0x1043A770
_MKV_EDITION_ENTRY   = 0x45B9
_MKV_EDITION_FLAG_DEFAULT = 0x45DB
_MKV_EDITION_FLAG_HIDDEN  = 0x45BD
_MKV_EDITION_FLAG_ORDERED = 0x45DD
_MKV_CHAPTER_ATOM    = 0xB6
_MKV_CHAPTER_UID     = 0x73C4
_MKV_CHAPTER_TIME_START = 0x91
_MKV_CHAPTER_TIME_END   = 0x92
_MKV_CHAPTER_FLAG_HIDDEN  = 0x98
_MKV_CHAPTER_FLAG_ENABLED = 0x4598
_MKV_CHAPTER_DISPLAY = 0x80
_MKV_CHAP_STRING     = 0x85
_MKV_CHAP_LANGUAGE   = 0x437C
_MKV_CHAPTER_PROCESS = 0x6944
_MKV_CHAP_PROC_CODEC_ID = 0x6955
_MKV_CHAP_PROC_PRIVATE  = 0x450D
_MKV_CHAP_PROC_COMMAND  = 0x6911
_MKV_CHAP_PROC_TIME     = 0x6922
_MKV_CHAP_PROC_DATA     = 0x6933

_MKV_CLUSTER         = 0x1F43B675
_MKV_TIMECODE        = 0xE7
_MKV_SIMPLEBLOCK     = 0xA3


def _mkv_dvd_command(opcode_word: int, ops: bytes = b'\x00' * 6) -> bytes:
    """An 8-byte DVD VM opcode. opcode_word is the first 2 bytes (big-
    endian); ``ops`` provides bytes 2..7 of the command word."""
    assert len(ops) == 6
    return struct.pack('>H', opcode_word) + ops


def _build_mkv_dvd_chapters_seed() -> bytes:
    """A short Matroska file with:
      - EBMLHeader (doctype=matroska)
      - Segment containing Info (timecode_scale=1ms), one bogus subtitle
        Track, a Chapters element with one EditionEntry → ChapterAtom that
        carries a DVD ChapterProcess (codec_id=1) plus enter / during /
        leave commands covering a representative slice of the DVD VM
        opcode table (NOP, JUMP_TT, CALLSS, JUMPSS, JUMP_PG_PGC, SET_GPRM,
        compare-and-branch tests, etc.), and a tiny single-block Cluster
        so demux_Demux runs at least once and Enter() fires."""

    # EBML Header
    ebml_body  = _mkv_uint(_MKV_EBML_VERSION, 1)
    ebml_body += _mkv_uint(_MKV_EBML_READVER, 1)
    ebml_body += _mkv_str(_MKV_DOCTYPE, b'matroska')
    ebml_body += _mkv_uint(_MKV_DOCTYPE_VER, 4)
    ebml_body += _mkv_uint(_MKV_DOCTYPE_RDVER, 2)
    ebml = _mkv_elem(_MKV_EBML, ebml_body)

    # Info — timescale = 1 ms; Duration in timecode units so that
    # matroska_segment_c::i_duration becomes non-zero and the non-ordered
    # virtual-chapter retiming gives the top-level vchap a non-zero range
    # (otherwise getChapterbyTimecode(0) skips it and the edition's DVD
    # codec commands never reach Enter()).  Duration encoded as IEEE
    # double (8 bytes, big-endian, value = 1000 timecode units = 1 s).
    info_body  = _mkv_bin(_MKV_TIMECODE_SCALE,
                          (1_000_000).to_bytes(3, 'big'))   # 1 ms ticks
    info_body += _mkv_bin(_MKV_DURATION, struct.pack('>d', 1000.0))
    info_body += _mkv_str(_MKV_MUXAPP, b'oss-fuzz-vlc')
    info_body += _mkv_str(_MKV_WRITEAPP, b'oss-fuzz-vlc')
    info = _mkv_elem(_MKV_INFO, info_body)

    # One subtitle track so the demuxer doesn't bail on "no tracks".
    track_body  = _mkv_uint(_MKV_TRACK_NUMBER, 1)
    track_body += _mkv_bin(_MKV_TRACK_UID, (1).to_bytes(4, 'big'))
    track_body += _mkv_uint(_MKV_TRACK_TYPE, 0x11)            # subtitle
    track_body += _mkv_str(_MKV_CODEC_ID, b'S_TEXT/UTF8')
    track_body += _mkv_uint(_MKV_FLAG_LACING, 0)
    tracks = _mkv_elem(_MKV_TRACKS, _mkv_elem(_MKV_TRACK_ENTRY, track_body))

    # DVD chapter commands.  Each command is 8 bytes; ProcessData is a
    # blob of (count) opcodes prefixed by the count byte (chapter_command_
    # dvd.cpp::EnterLeaveHelper at line 56:
    #     i_size = std::min<size_t>( *p_data++, ((*it).GetSize() - 1) >> 3 )
    # so the first byte is the command count and the rest is count*8
    # bytes.
    enter_commands = bytes()
    enter_commands += _mkv_dvd_command(0x0000)                  # NOP
    enter_commands += _mkv_dvd_command(0x0020)                  # NOP2
    enter_commands += _mkv_dvd_command(0x3010,  b'\x00\x00\x01\x00\x00\x00')  # JumpTT 1
    enter_commands += _mkv_dvd_command(0x3030,  b'\x00\x00\x00\x00\x00\x00')  # CallSS PGC
    enter_commands += _mkv_dvd_command(0x3050,  b'\x80\x00\x02\x00\x40\x00')  # JumpSS VTSM
    enter_commands += _mkv_dvd_command(0x3060,  b'\x00\x00\x00\x00\x01\x02')  # JumpVTS_PTT
    enter_commands += _mkv_dvd_command(0x4070,  b'\x00\x01\x00\x00\x00\x05')  # JumpVTS_TT
    enter_commands += _mkv_dvd_command(0x5180,  b'\x00\x00\x00\x00\x00\x05')  # SetGPRM
    enter_commands += _mkv_dvd_command(0x6190,  b'\x00\x00\x00\x00\x00\x10')  # Compare
    # A handful of register-test prefixes: high nibble selects encoding
    # of CR1/CR2 in different command word slots.
    enter_commands += _mkv_dvd_command(0x21F0,  b'\x05\x00\x10\x00\x00\x00')  # IF EQ
    enter_commands += _mkv_dvd_command(0x4140,  b'\x05\x00\x00\x00\x00\x10')  # IF !EQ (alt enc)
    enter_commands += _mkv_dvd_command(0x6420,  b'\x05\x00\x00\x10\x00\x10')  # IF AND (alt2)
    private_data_enter = bytes([len(enter_commands) // 8]) + enter_commands

    leave_commands = (
        _mkv_dvd_command(0x0000)                           # NOP
        + _mkv_dvd_command(0x2030, b'\x00\x10\x00\x00\x00\x00')  # SET GPRM
        + _mkv_dvd_command(0x5000, b'\x00\x00\x00\x00\x00\x01')  # IF SUP
    )
    private_data_leave = bytes([len(leave_commands) // 8]) + leave_commands

    during_commands = (
        _mkv_dvd_command(0x0010)                            # NOP variant
        + _mkv_dvd_command(0x3000, b'\x80\x00\x02\x00\x40\x00')  # JumpSS VMGM Title
    )
    private_data_during = bytes([len(during_commands) // 8]) + during_commands

    # Build ChapterProcess element: codec_id=1 (DVD), private data, three
    # ChapterProcessCommand sub-elements with different ProcessTime values
    # (0=BEFORE, 1=DURING, 2=AFTER) so all three buckets in
    # chapter_command.cpp::AddCommand are filled.

    # DVD level for the "Title" level (TT == 0x28) — the private blob is
    # 4 bytes when GetTitleNumber() reads it (level + 0x00 + title_msb + title_lsb).
    chap_private = bytes([0x28, 0x00, 0x00, 0x01])
    chap_process_body  = _mkv_uint(_MKV_CHAP_PROC_CODEC_ID, 1)
    chap_process_body += _mkv_bin(_MKV_CHAP_PROC_PRIVATE, chap_private)

    def _make_command(time_val: int, blob: bytes) -> bytes:
        cmd_body  = _mkv_uint(_MKV_CHAP_PROC_TIME, time_val)
        cmd_body += _mkv_bin(_MKV_CHAP_PROC_DATA, blob)
        return _mkv_elem(_MKV_CHAP_PROC_COMMAND, cmd_body)

    chap_process_body += _make_command(0, private_data_enter)
    chap_process_body += _make_command(1, private_data_during)
    chap_process_body += _make_command(2, private_data_leave)
    chap_process = _mkv_elem(_MKV_CHAPTER_PROCESS, chap_process_body)

    # ChapterAtom 1 with display name + DVD chapter process.
    chap_display = _mkv_elem(_MKV_CHAPTER_DISPLAY,
                             _mkv_str(_MKV_CHAP_STRING, b'Chapter 1')
                             + _mkv_str(_MKV_CHAP_LANGUAGE, b'eng'))
    chap_atom_body  = _mkv_uint(_MKV_CHAPTER_UID, 1)
    chap_atom_body += _mkv_uint(_MKV_CHAPTER_FLAG_HIDDEN, 0)
    chap_atom_body += _mkv_uint(_MKV_CHAPTER_FLAG_ENABLED, 1)
    chap_atom_body += _mkv_uint(_MKV_CHAPTER_TIME_START, 0)
    chap_atom_body += _mkv_uint(_MKV_CHAPTER_TIME_END, 0x10000)
    chap_atom_body += chap_display
    chap_atom_body += chap_process
    chap_atom_1 = _mkv_elem(_MKV_CHAPTER_ATOM, chap_atom_body)

    # A second ChapterAtom carrying a different DVD level (PGC = 0x20) so
    # the GetTitleNumber path matches a different branch.  EndTime must
    # be present in ordered editions, otherwise the chapter is dropped.
    chap_private_2 = bytes([0x20, 0x00, 0x00, 0x02])
    chap_process_2_body  = _mkv_uint(_MKV_CHAP_PROC_CODEC_ID, 1)
    chap_process_2_body += _mkv_bin(_MKV_CHAP_PROC_PRIVATE, chap_private_2)
    chap_process_2_body += _make_command(0, private_data_enter)
    chap_process_2 = _mkv_elem(_MKV_CHAPTER_PROCESS, chap_process_2_body)
    chap_atom_2_body  = _mkv_uint(_MKV_CHAPTER_UID, 2)
    chap_atom_2_body += _mkv_uint(_MKV_CHAPTER_TIME_START, 0x10000)
    chap_atom_2_body += _mkv_uint(_MKV_CHAPTER_TIME_END,   0x20000)
    chap_atom_2_body += chap_process_2
    chap_atom_2 = _mkv_elem(_MKV_CHAPTER_ATOM, chap_atom_2_body)

    # A third ChapterAtom carrying a native (Matroska script) codec_id=0
    # so chapter_command_script.cpp also picks up coverage.
    chap_process_3_body  = _mkv_uint(_MKV_CHAP_PROC_CODEC_ID, 0)
    chap_process_3_body += _mkv_bin(_MKV_CHAP_PROC_PRIVATE, b'')
    chap_process_3_body += _make_command(0, b'\x01' + _mkv_dvd_command(0x0000))
    chap_process_3 = _mkv_elem(_MKV_CHAPTER_PROCESS, chap_process_3_body)
    chap_atom_3_body  = _mkv_uint(_MKV_CHAPTER_UID, 3)
    chap_atom_3_body += _mkv_uint(_MKV_CHAPTER_TIME_START, 0x20000)
    chap_atom_3_body += _mkv_uint(_MKV_CHAPTER_TIME_END,   0x30000)
    chap_atom_3_body += chap_process_3
    chap_atom_3 = _mkv_elem(_MKV_CHAPTER_ATOM, chap_atom_3_body)

    # EditionEntry — default + ordered.  Ordered editions make the demuxer
    # iterate chapters in declaration order using their explicit
    # ChapterTime{Start,End} values, which means our chapter atoms become
    # the actual vchapters list (not sub-chapters of a wrapping edition
    # vchapter) and getChapterbyTimecode(0) returns chapter 1, whose
    # DVD ChapterProcessCommands are then run by Enter().
    edition_body  = _mkv_bin(_MKV_EDITION_FLAG_DEFAULT, b'\x01')
    edition_body += _mkv_bin(_MKV_EDITION_FLAG_ORDERED, b'\x01')
    edition_body += chap_atom_1 + chap_atom_2 + chap_atom_3
    edition = _mkv_elem(_MKV_EDITION_ENTRY, edition_body)
    chapters = _mkv_elem(_MKV_CHAPTERS, edition)

    # Cluster — one SimpleBlock so Demux() runs at least once and
    # UpdateCurrentToChapter() can invoke Enter() before EOF.
    cluster_body  = _mkv_uint(_MKV_TIMECODE, 0)
    block_payload = bytes([0x81, 0x00, 0x00, 0x00]) + b'x'      # track=1, ts=0
    cluster_body += _mkv_bin(_MKV_SIMPLEBLOCK, block_payload)
    cluster = _mkv_elem(_MKV_CLUSTER, cluster_body)

    # Segment: Info + Tracks + Chapters + Cluster
    segment_body = info + tracks + chapters + cluster
    segment = _mkv_elem(_MKV_SEGMENT, segment_body)

    return ebml + segment


def gen_mkv(root):
    out = os.path.join(root, 'seeds', 'mkv')
    os.makedirs(out, exist_ok=True)
    _write(os.path.join(out, 'dvd_chapter_commands.mkv'),
           _build_mkv_dvd_chapters_seed())


# ──────────────────────────────────────────────────
#  MP4 extras (modules/demux/mp4/libmp4.c)
# ──────────────────────────────────────────────────
#
# The upstream vlc-fuzz-corpus seeds in seeds/mp4/ (aac_audio.mp4,
# avc_video.mp4, fragmented.mp4, with_sidx.mp4, …) exercise the common
# ftyp/moov/trak/mdia/stbl tree, leaving several specialized libmp4.c
# parsers at 0% coverage in the production OSS-Fuzz report:
#
#   * MP4_ReadBox_st3d / prhd / equi / cbmp   — spherical/VR metadata
#     (sv3d > proj > {prhd,equi,cbmp}; st3d at any depth)
#   * MP4_ReadBox_tfrf / tfxd / XML360         — Smooth Streaming /
#     Google360 uuid-typed boxes routed through MP4_ReadBox_uuid
#   * MP4_ReadBox_urn                          — DataReference 'urn '
#     variant; the upstream corpus only uses 'url '
#
# The seeds below place those boxes directly under a minimal moov so
# MP4_BoxGetRoot walks them during demux_New, even though mp4.c::Open
# subsequently fails (no trak with ES). Box parsing completes before
# that failure, which is the only requirement for hitting the parsers.
# The mp4 dictionary is also enlarged from 3 tokens to ~200 by
# harvesting every ATOM_xxxx 4CC define from libmp4.h so libfuzzer
# mutation has a chance of synthesizing the dispatch keys.

UUID_TFRF = bytes([0xd4, 0x80, 0x7e, 0xf2, 0xca, 0x39, 0x46, 0x95,
                   0x8e, 0x54, 0x26, 0xcb, 0x9e, 0x46, 0xa7, 0x9f])
UUID_TFXD = bytes([0x6d, 0x1d, 0x9b, 0x05, 0x42, 0xd5, 0x44, 0xe6,
                   0x80, 0xe2, 0x14, 0x1d, 0xaf, 0xf7, 0x57, 0xb2])
UUID_XML360 = bytes([0xff, 0xcc, 0x82, 0x63, 0xf8, 0x55, 0x4a, 0x93,
                     0x88, 0x14, 0x58, 0x7a, 0x02, 0x52, 0x1f, 0xdd])


def mp4_uuid_box(uuid: bytes, payload: bytes) -> bytes:
    assert len(uuid) == 16
    return box(b'uuid', uuid + payload)


def _mp4_ftyp_mp42() -> bytes:
    # mp42/isom brands fall through the default branch in mp4.c::Open;
    # heic/heix/mif1/jpeg/avci/avif/f4v are explicitly diverted to the
    # heif submodule and would cause our seed to be rejected outright.
    return box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42isom')


def _mp4_mvhd_minimal() -> bytes:
    body  = struct.pack('>II', 0, 0)
    body += struct.pack('>II', 1000, 0)
    body += struct.pack('>I', 0x00010000)
    body += struct.pack('>H', 0x0100)
    body += bytes(10)
    body += struct.pack('>9I',
                        0x00010000, 0, 0,
                        0, 0x00010000, 0,
                        0, 0, 0x40000000)
    body += bytes(24)
    body += struct.pack('>I', 2)
    return fullbox(b'mvhd', 0, 0, body)


def seed_mp4_spherical() -> bytes:
    """Drives MP4_ReadBox_st3d / prhd / equi / cbmp by carrying the
       sv3d > proj > {prhd,equi,cbmp} chain plus a sibling st3d. sv3d
       and st3d both have i_parent=0 in the dispatch table so they
       parse at any depth; placing them under moov keeps the seed
       small."""
    prhd = fullbox(b'prhd', 0, 0,
                   struct.pack('>iii', 0, 0, 0))
    equi = fullbox(b'equi', 0, 0,
                   struct.pack('>IIII', 0, 0, 0, 0))
    cbmp = fullbox(b'cbmp', 0, 0,
                   struct.pack('>II', 0, 0))
    proj = box(b'proj', prhd + equi + cbmp)
    sv3d = box(b'sv3d', proj)
    st3d = fullbox(b'st3d', 0, 0, bytes([0x00]))
    moov = box(b'moov', _mp4_mvhd_minimal() + sv3d + st3d)
    return _mp4_ftyp_mp42() + moov


def seed_mp4_uuid_boxes() -> bytes:
    """Hits MP4_ReadBox_uuid's UUID-dispatch ladder for the three
       handled extended types: TfrfBoxUUID, TfxdBoxUUID, XML360BoxUUID.
       MP4_ReadBox_tfrf / tfxd / XML360 are all 0% covered in the
       production report."""
    tfrf_payload = (bytes([0x00, 0x00, 0x00, 0x00])
                    + bytes([0x01])
                    + struct.pack('>II', 0, 100))
    tfrf = mp4_uuid_box(UUID_TFRF, tfrf_payload)

    tfxd_payload = (bytes([0x00, 0x00, 0x00, 0x00])
                    + struct.pack('>II', 0, 100))
    tfxd = mp4_uuid_box(UUID_TFXD, tfxd_payload)

    xml360 = mp4_uuid_box(
        UUID_XML360,
        b'<rdf:Description'
        b' xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        b' xmlns:GSpherical="http://ns.google.com/videos/1.0/spherical/"'
        b' GSpherical:Spherical="true"'
        b' GSpherical:Stitched="true"'
        b' GSpherical:ProjectionType="equirectangular"/>\x00')

    moov = box(b'moov', _mp4_mvhd_minimal() + tfrf + tfxd + xml360)
    return _mp4_ftyp_mp42() + moov


def seed_mp4_dref_urn() -> bytes:
    """Reaches MP4_ReadBox_urn by emitting a urn entry inside a dref
       at moov-root. Both dref and urn carry i_parent=0 in the dispatch
       table so they parse outside the usual trak/mdia/minf/dinf chain."""
    urn = fullbox(b'urn ', 0, 0,
                  b'urn:example:fuzz\x00urn:example:loc\x00')
    dref_payload = struct.pack('>I', 1) + urn
    dref = fullbox(b'dref', 0, 0, dref_payload)
    moov = box(b'moov', _mp4_mvhd_minimal() + dref)
    return _mp4_ftyp_mp42() + moov


MP4_EXTRA_SEEDS = {
    'spherical.mp4':  seed_mp4_spherical,
    'uuid_boxes.mp4': seed_mp4_uuid_boxes,
    'dref_urn.mp4':   seed_mp4_dref_urn,
}


# Curated fallback used when libmp4.h isn't readable (e.g. running
# generate_seeds.py outside the container). Kept in sync with the
# dispatch table in libmp4.c (5044+) but trimmed to atoms whose
# 4CCs are printable ASCII and parser-relevant.
_MP4_FALLBACK_ATOMS = [
    # Structural / brand
    'ftyp', 'moov', 'foov', 'moof', 'mdat', 'free', 'skip', 'wide',
    'udta', 'pnot', 'pict', 'uuid', 'styp', 'cmov', 'dcom', 'cmvd',
    'sidx',
    # Track / media
    'trak', 'tkhd', 'tref', 'load', 'mdia', 'mdhd', 'hdlr', 'minf',
    'vmhd', 'smhd', 'hmhd', 'nmhd', 'dinf', 'dref', 'url ', 'urn ',
    'stbl', 'elst', 'edts', 'mvhd', 'iods',
    # Sample table
    'stsd', 'stts', 'stsc', 'stsz', 'stz2', 'stco', 'co64', 'ctts',
    'cslg', 'stss', 'stsh', 'sdtp', 'padb', 'stps',
    # Sample groups / aux
    'sbgp', 'sgpd', 'saio', 'saiz',
    # Movie extension / fragments
    'mvex', 'mehd', 'trex', 'leva', 'moof', 'mfhd', 'traf', 'tfhd',
    'trun', 'tfdt', 'tfra', 'mfra', 'mfro', 'sidx', 'prft', 'emsg',
    'subs',
    # User data / metadata
    'name', 'kind', 'chap', 'sync', 'hint', 'cont', 'alis', 'rsrc',
    'gnre', 'covr', 'tags', 'ilst', 'data', 'mean', 'keys', 'chpl',
    'ID32', 'hdr3', 'mvcg', 'mvci',
    # Visual sample entries / codec config
    'avc1', 'avc3', 'avc4', 'hvc1', 'hev1', 'hvt1', 'lhv1', 'av01',
    'vp08', 'vp09', 'mp4v', 'mp4a', 'jpeg', 'jpgC', 'jp2 ', 'mjp2',
    'btrt', 'avcC', 'hvcC', 'av1C', 'dvcC', 'dvvC', 'lhvC', 'vpcC',
    'fiel', 'pasp', 'colr', 'clap', 'esds', 'jpeC', 'dac3', 'dec3',
    'enda', 'chnl', 'chan', 'mhaC', 'mhap', 'iso2', 'iso3', 'iso6',
    # HDR / display
    'clli', 'mdcv', 'smdm', 'coll',
    # Spherical / VR
    'sv3d', 'st3d', 'proj', 'prhd', 'equi', 'cbmp', 'svhd',
    # Encryption
    'sinf', 'frma', 'schm', 'schi', 'tenc', 'pssh', 'senc', 'sbgp',
    'sgpd', 'cbcs', 'cbc1', 'cenc', 'cens',
    # HEIF / item-based
    'meta', 'pitm', 'iinf', 'infe', 'iloc', 'iref', 'dimg', 'thmb',
    'cdsc', 'auxl', 'iprp', 'ipco', 'ipma', 'ispe', 'pixi', 'irot',
    'imir', 'idat', 'grid', 'iovl', 'iden', 'hvcC', 'avcC', 'av1C',
    'jpeC', 'lhvC',
    # Apple / QuickTime / metadata atom IDs
    'wave', 'alac', 'in24', 'in32', 'lpcm', 'sowt', 'twos', 'ulaw',
    'alaw', 'samr', 'sawb', 'sawp', '.mp3', '.MP3', 'ms\x00\x55',
    # Branding strings frequently checked in mp4.c
    'mp42', 'mp41', 'isom', 'iso2', 'iso6', 'iso8', 'qt  ', '3gp4',
    '3gp5', 'M4A ', 'M4V ', 'mp71', 'avif', 'avis', 'heic', 'heix',
    'mif1', 'msf1', 'dash', 'cmfc', 'piff', 'CAEP', 'caaa', 'caqv',
    'crsm', 'cvmp', 'sams', 'msnv', 'm4a ',
    # Misc / 3GPP / Nero / Smooth streaming
    'tfrf', 'tfxd', 'kind', 'load', 'rmra', 'rmcs', 'rmdr',
    'rmla', 'rmvc', 'rmqu', 'rmcd', 'rdrf', 'WLOC', 'WCOL',
    'WTRK', 'WSEL',
]


def _harvest_libmp4_atoms() -> list:
    """Parse libmp4.h for ATOM_xxx VLC_FOURCC(..) defines so the mp4
       dictionary stays in sync with the source. Falls back to the
       curated _MP4_FALLBACK_ATOMS when libmp4.h isn't reachable
       (running outside the container during development)."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, 'vlc', 'modules', 'demux', 'mp4', 'libmp4.h'),
        '/src/vlc/modules/demux/mp4/libmp4.h',
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        return list(_MP4_FALLBACK_ATOMS)
    tokens = set()
    pat = re.compile(
        r"VLC_FOURCC\(\s*'(.)'\s*,\s*'(.)'\s*,\s*'(.)'\s*,\s*'(.)'\s*\)")
    with open(path) as f:
        for line in f:
            for m in pat.finditer(line):
                tokens.add(''.join(m.groups()))
    # Always include the curated set so spherical/uuid/etc. tokens
    # survive even if libmp4.h evolves and renames atoms.
    tokens.update(_MP4_FALLBACK_ATOMS)
    return sorted(tokens)


def mp4_dictionary() -> str:
    tokens = _harvest_libmp4_atoms()
    lines = ['# MP4 / ISOBMFF box / brand tokens harvested from libmp4.h']
    for t in tokens:
        # libFuzzer rejects unprintable bytes outside \x escapes, and
        # rejects unbalanced quotes; encode every byte as \xHH.
        encoded = ''.join('\\x%02x' % b for b in t.encode('latin-1'))
        lines.append('"' + encoded + '"')
    return '\n'.join(lines) + '\n'


# ──────────────────────────────────────────────────
#  CEA-708 caption seeds (modules/codec/cea708.c)
# ──────────────────────────────────────────────────
#
# cea708.c (the DTVCC service-block / window command decoder, ~1200 lines) was
# only ~9% covered: nothing in the corpus drove it. It is reached only via a
# real cc.c decoder loaded on a caption ES, NOT via the SEI cc_data extracted by
# the H.264/H.265 packetizers — the test harness discards packetizer pf_get_cc
# output (test/src/input/decoder.c). The one container that emits a standalone
# VLC_CODEC_CEA708 ES is MP4: a 'clcp' handler track with a 'c708' sample entry
# (modules/demux/mp4/{essetup,mp4}.c). The full reachable path is:
#
#   mp4 demux (clcp/c708 track) -> SPU ES VLC_CODEC_CEA708 -> cc.c spu decoder
#   -> MP4_CDP_Convert: each sample is a QuickTime 'ccdp' atom wrapping an
#      ST334-2 CDP, parsed by cc.h cc_Extract(CC_PAYLOAD_CDP) into cc triplets
#   -> cc.c Convert(): triplets with cc_type 3/2 -> CEA708 DTVCC demuxer
#   -> service blocks (service #1, matching c708 default cc.i_channel 0)
#   -> CEA708_Decoder_Push -> the C0/C1/G0/G1/G2G3/P16 command parser.
#
# These seeds emit valid MP4 c708 tracks whose samples carry DTVCC service
# blocks exercising DefineWindow (DF0..DF7), SetPen{Attributes,Color,Location},
# SetWindowAttributes, window display/clear/toggle/hide/delete, delays, reset,
# G0/G1/G2-G3/P16 text, and rows filled to the screen edge in all four
# print/scroll directions to drive Window_{Forward,CarriageReturn,Scroll,
# Truncate,MaxCol,MinCol}. They land in seeds/mp4/ (the mp4 demux target).

def _cea_mvhd():
    p = struct.pack('>IIII', 0, 0, 1000, 0) + struct.pack('>I', 0x10000)
    p += struct.pack('>H', 0x0100) + b'\x00' * 10
    p += struct.pack('>9i', 0x10000,0,0, 0,0x10000,0, 0,0,0x40000000)
    p += b'\x00' * 24 + struct.pack('>I', 2)
    return fullbox(b'mvhd', 0, 0, p)

def _cea_tkhd():
    p = struct.pack('>IIIII', 0,0,1,0,0) + b'\x00' * 8
    p += struct.pack('>hhhh', 0,0,0,0)
    p += struct.pack('>9i', 0x10000,0,0, 0,0x10000,0, 0,0,0x40000000)
    p += struct.pack('>II', 0, 0)
    return fullbox(b'tkhd', 0, 0x000007, p)   # enabled | in movie | in preview

def _cea_mdhd():
    return fullbox(b'mdhd', 0, 0, struct.pack('>IIII', 0,0,1000,0) +
                   struct.pack('>HH', 0x55c4, 0))

def _cea_stsd_c708():
    entry = box(b'c708', b'\x00' * 6 + struct.pack('>H', 1))  # 6 reserved + dref idx
    return fullbox(b'stsd', 0, 0, struct.pack('>I', 1) + entry)

def _cea_build_mp4(samples):
    sizes = [len(s) for s in samples]
    n = len(samples)
    def stbl(chunk_off):
        return box(b'stbl',
            _cea_stsd_c708() +
            fullbox(b'stts',0,0, struct.pack('>I',1) + struct.pack('>II', n, 1000)) +
            fullbox(b'stsc',0,0, struct.pack('>I',1) + struct.pack('>III', 1, n, 1)) +
            fullbox(b'stsz',0,0, struct.pack('>II', 0, n) +
                    b''.join(struct.pack('>I', s) for s in sizes)) +
            fullbox(b'stco',0,0, struct.pack('>I',1) + struct.pack('>I', chunk_off)))
    def moov(chunk_off):
        minf = box(b'minf', box(b'dinf', fullbox(b'dref',0,0, struct.pack('>I',1) +
                   fullbox(b'url ',0,1,b''))) + stbl(chunk_off))
        mdia = box(b'mdia', _cea_mdhd() + hdlr(b'clcp') + minf)
        return box(b'moov', _cea_mvhd() + box(b'trak', _cea_tkhd() + mdia))
    ftypb = ftyp(b'isom', [b'isom', b'mp42'])
    chunk_off = len(ftypb) + len(moov(0)) + 8     # moov size is offset-independent
    return ftypb + moov(chunk_off) + box(b'mdat', b''.join(samples))

# DTVCC cc-triplet byte0: marker bits | valid bit (0x04) | cc_type. type 3 =
# DTVCC packet header, type 2 = continuation (cc.c routes both to the 708 demux).
def _cea_cdp_sample(command_block, seq):
    sb = bytes([(1 << 5) | len(command_block)]) + command_block   # service #1
    P = bytearray(sb)
    if len(P) % 2 == 0:
        P.append(0x00)                            # odd length -> clean packing
    code = (len(P) + 1) // 2
    trips = [bytes([0xFF, code, P[0]])]           # 0xFF: valid, cc_type 3
    i = 1
    while i < len(P):
        trips.append(bytes([0xFE, P[i], P[i+1]])) # 0xFE: valid, cc_type 2
        i += 2
    assert len(trips) <= 31
    ccdata = bytes([0x72, 0xE0 | len(trips)]) + b''.join(trips)
    cdp = bytearray([0x96, 0x69, 0, 0x3F, 0x40, (seq >> 8) & 0xFF, seq & 0xFF]) + ccdata
    cdp[2] = len(cdp) & 0xFF                       # cdp_length
    return box(b'ccdp', bytes(cdp))

def _cea_command_blocks():
    DF0, DF7 = 0x98, 0x9F
    blocks = [
        # DefineWindow 0, pen/window attributes, pen location, text, flush.
        bytes([DF0,0x27,0x00,0x00,0x12,0x20,0x09, 0x90,0x4A,0xC5, 0x91,0x7F,0x80,0x2A,
               0x97,0x40,0x00,0x3C,0x21, 0x92,0x01,0x02, 0x48,0x69, 0x03]),
        # Window visibility ops + delay/cancel.
        bytes([0x89,0x01, 0x80, 0x88,0x01, 0x8B,0x01, 0x8A,0x01, 0x8D,0x05, 0x8E]),
        # DefineWindow 1 (relative), G1 / EXT1+G2 / P16 / C0 controls.
        bytes([0x99,0x20,0x80,0x10,0x23,0x10,0x12, 0xA1, 0x10,0x30, 0x18,0x00,0x41,
               0x08, 0x0C, 0x0D, 0x0E, 0x7F, 0x03]),
        # DefineWindow 7, text, display, delete-all, reset.
        bytes([DF7,0x20,0x00,0x00,0x11,0x10,0x00, 0x87, 0x54,0x56, 0x89,0x80,
               0x8C,0xFF, 0x8F]),
    ]
    # Small windows in all 4 print/scroll directions, filled with text + CRs to
    # drive Forward/CarriageReturn/Scroll/Truncate across every direction branch.
    for d in range(4):
        win = 2 + d
        blocks += [
            bytes([0x98 + win, 0x27,0x00,0x00,0x11,0x04,0x09]),
            bytes([0x97, 0x00,0x00, 0x40 | (d << 4) | (d << 2), 0x12]),
            bytes([0x80 + win]),
            bytes([0x41,0x42,0x43,0x20,0x44,0x45,0x20,0x46, 0x0D,0x0D,0x0D,0x08,0x0C,0x03]),
            bytes([0x47,0x48,0x49,0x20,0x4A,0x4B, 0x0D,0x0D,0x0E,0x03]),
        ]
    # LTR row filled to the right edge (col 41) -> Truncate(LTR) + MaxCol.
    blocks += [
        bytes([0x9E,0x27,0x00,0x00,0x11,0x20,0x09]),
        bytes([0x97,0x00,0x00,0x00,0x00]),
        bytes([0x86, 0x92,0x00,0x00]),
        bytes([0x41]*28), bytes([0x41]*28),
        bytes([0x0D, 0x03]),
    ]
    # RTL row filled to the left edge (col 0) -> Truncate(RTL) + MinCol.
    blocks += [
        bytes([0x9D,0x27,0x00,0x00,0x11,0x20,0x09]),
        bytes([0x97,0x00,0x00,0x14,0x00]),
        bytes([0x85, 0x92,0x00,0x29]),
        bytes([0x42]*28), bytes([0x42]*28),
        bytes([0x0D, 0x03]),
    ]
    # P16 across all three UTF-8 width branches, then display everything.
    blocks += [
        bytes([0x18,0x00,0x41, 0x18,0x04,0x00, 0x18,0x30,0x42, 0x03]),
        bytes([0x89, 0xFF, 0x03]),
    ]
    return blocks


def gen_cea708(root):
    seed_dir = os.path.join(root, 'seeds', 'mp4')
    os.makedirs(seed_dir, exist_ok=True)
    blocks = _cea_command_blocks()
    # One full program seed (all commands), plus a couple of split variants so
    # the fuzzer has shorter, easily-mutable caption samples to start from.
    variants = {
        'cea708_dtvcc_full.mp4': blocks,
        'cea708_dtvcc_windows.mp4': blocks[:4],
        'cea708_dtvcc_scroll.mp4': blocks[4:24],
    }
    for name, blks in variants.items():
        samples = [_cea_cdp_sample(b, i) for i, b in enumerate(blks)]
        data = _cea_build_mp4(samples)
        _write(os.path.join(seed_dir, name), data)
        print(f'  seeds/mp4/{name}: {len(data)} bytes, {len(samples)} CDP samples')


def gen_mp4_extras(root):
    seed_dir = os.path.join(root, 'seeds', 'mp4')
    dict_dir = os.path.join(root, 'dictionaries')
    os.makedirs(seed_dir, exist_ok=True)
    os.makedirs(dict_dir, exist_ok=True)
    for filename, gen in MP4_EXTRA_SEEDS.items():
        data = gen()
        _write(os.path.join(seed_dir, filename), data)
    with open(os.path.join(dict_dir, 'mp4.dict'), 'w') as f:
        f.write(mp4_dictionary())
    print('  dictionaries/mp4.dict written')


# ──────────────────────────────────────────────────
#  GME seeds (modules/demux/gme.c -> contrib libgme)
# ──────────────────────────────────────────────────
#
# gme.c Open() peeks only the first 4 bytes and accepts the file when
# gme_identify_header() recognises the magic; libgme then parses the format
# header and emulates the embedded CPU/sound chip in Demux(). The existing
# corpus has no gme seeds at all, so the plugin and the libgme loaders and
# CPU cores (6502/Z80/SPC700/GB/HuC6280…) are currently unreached.
#
# We emit one minimal but magic-valid file per supported format. A bare header
# passes Open() and starts the emulator; the fuzzer mutates outward from these
# into the per-format parsers and the CPU/APU cores.

def _gme_nsf():
    """NSF (NES, 6502 core)."""
    h = bytearray(128)
    h[0:5] = b"NESM\x1a"
    h[5] = 1                                   # version
    h[6] = 1                                   # total songs
    h[7] = 1                                   # starting song (1-based)
    h[8:10]   = (0x8000).to_bytes(2, "little") # load addr
    h[10:12]  = (0x8000).to_bytes(2, "little") # init addr
    h[12:14]  = (0x8000).to_bytes(2, "little") # play addr
    h[110:112] = (0x411A).to_bytes(2, "little")# NTSC speed
    h[120:122] = (0x4E20).to_bytes(2, "little")# PAL speed
    return bytes(h) + bytes([0x60]) * 64       # program: RTS sled at $8000


def _gme_gbs():
    """GBS (Game Boy, LR35902 core)."""
    h = bytearray(0x70)
    h[0:4] = b"GBS\x01"
    h[4] = 1                                    # song count
    h[5] = 1                                    # first song
    for off, val in [(6, 0x0400), (8, 0x0400), (10, 0x0400), (12, 0xFFFE)]:
        h[off:off+2] = val.to_bytes(2, "little")  # load/init/play/sp
    return bytes(h) + bytes(64)


def _gme_vgm():
    """VGM 1.50 (chip command stream)."""
    h = bytearray(0x40)
    h[0:4] = b"Vgm "
    h[8:12]    = (0x150).to_bytes(4, "little")            # version 1.50
    h[0x34:0x38] = (0x40 - 0x34).to_bytes(4, "little")    # data offset
    body = bytes([0x66])                                  # end-of-sound marker
    h[4:8]     = (0x40 + len(body) - 4).to_bytes(4, "little")  # EOF offset
    return bytes(h) + body


def _gme_magic_only(magic: bytes, size: int) -> bytes:
    return magic + bytes(max(0, size - len(magic)))


def gen_gme(root):
    seed_dir = os.path.join(root, "seeds", "gme")
    seeds = {
        "song.nsf": _gme_nsf(),
        "song.gbs": _gme_gbs(),
        "song.vgm": _gme_vgm(),
        # SPC700 RAM dump is fixed-size 0x10200; magic = first 4 bytes "SNES".
        "song.spc": _gme_magic_only(b"SNES-SPC700 Sound File Data v0.30", 0x10200),
        "song.ay":  _gme_magic_only(b"ZXAYEMUL", 128),
        "song.kss": _gme_magic_only(b"KSCC", 128),
        "song.gym": _gme_magic_only(b"GYMX", 428),
        # The HES format is exercised via the "HESM" dictionary entry rather
        # than a dedicated seed.
    }
    for name, data in seeds.items():
        _write(os.path.join(seed_dir, name), data)

    dict_path = os.path.join(root, "dictionaries", "gme.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "w") as f:
        f.write("# libgme format magics recognised by gme_identify_header()\n")
        for tag in ['NESM\\x1a', 'GBS\\x01', 'Vgm ', 'ZXAYEMUL',
                    'KSCC', 'KSSX', 'HESM', 'GYMX', 'NSFE', 'SNES-SPC700']:
            f.write(f'"{tag}"\n')
    print("  dictionaries/gme.dict written")


# ──────────────────────────────────────────────────
#  MOD seeds (modules/demux/mod.c -> contrib libmodplug)
# ──────────────────────────────────────────────────
#
# The harness forces the "mod" demuxer by name, so demux->obj.force is true and
# mod.c skips its extension Validate(); any non-empty file < 500MB is handed
# straight to libmodplug, which probes every loader by content. The existing
# corpus has no mod seeds, so libmodplug's loaders (load_it/load_s3m/load_mod/
# load_xm/…) are currently unreached. We provide one minimal file per major
# loader so each format's parser is seeded; the fuzzer mutates header
# counts/offsets from here.

def _mod_it():
    """Impulse Tracker — 'IMPM' magic at offset 0."""
    h = bytearray(0xC0)
    h[0:4] = b"IMPM"
    # song name (26 bytes) left zero
    h[0x20:0x22] = (0).to_bytes(2, "little")   # OrdNum
    h[0x22:0x24] = (0).to_bytes(2, "little")   # InsNum
    h[0x24:0x26] = (0).to_bytes(2, "little")   # SmpNum
    h[0x26:0x28] = (0).to_bytes(2, "little")   # PatNum
    h[0x28:0x2A] = (0x0214).to_bytes(2, "little")  # created w/ tracker version
    h[0x2A:0x2C] = (0x0200).to_bytes(2, "little")  # compatible version
    h[0x30] = 0x80                              # global volume
    h[0x32] = 0x80                              # mixing volume
    h[0x33] = 6                                 # initial speed
    h[0x34] = 0x7D                              # initial tempo
    return bytes(h) + b"\xff"                   # one order: end-of-song marker


def _mod_s3m():
    """ScreamTracker 3 — 'SCRM' magic at offset 0x2C."""
    h = bytearray(0x60)
    h[0x1C] = 0x1A                              # EOF marker
    h[0x1D] = 0x10                              # file type (module)
    h[0x20:0x22] = (0).to_bytes(2, "little")    # OrdNum
    h[0x22:0x24] = (0).to_bytes(2, "little")    # InsNum
    h[0x24:0x26] = (0).to_bytes(2, "little")    # PatNum
    h[0x28:0x2A] = (0x1320).to_bytes(2, "little")  # cwtv
    h[0x2A:0x2C] = (2).to_bytes(2, "little")    # file format info
    h[0x2C:0x30] = b"SCRM"
    h[0x30] = 6                                 # global volume
    h[0x31] = 6                                 # initial speed
    h[0x32] = 0x7D                              # initial tempo
    # 32 channel settings: all disabled (0xFF)
    return bytes(h) + b"\xff" * 32


def _mod_xm():
    """FastTracker 2 — 'Extended Module: ' magic at offset 0."""
    h = bytearray()
    h += b"Extended Module: "                   # 17 bytes
    h += b"seed".ljust(20, b"\x00")             # module name (20)
    h += b"\x1a"                                # 0x1A
    h += b"FastTracker v2.00   "                # tracker name (20)
    h += (0x0104).to_bytes(2, "little")         # version 1.04
    h += (0x0114).to_bytes(4, "little")         # header size (276)
    h += (1).to_bytes(2, "little")              # song length
    h += (0).to_bytes(2, "little")              # restart position
    h += (4).to_bytes(2, "little")              # number of channels
    h += (0).to_bytes(2, "little")              # number of patterns
    h += (0).to_bytes(2, "little")              # number of instruments
    h += (1).to_bytes(2, "little")              # flags (linear freq)
    h += (6).to_bytes(2, "little")              # default tempo
    h += (125).to_bytes(2, "little")            # default BPM
    h += bytes(256)                             # pattern order table
    return bytes(h)


def _mod_protracker():
    """Amiga ProTracker — 'M.K.' tag at offset 1080."""
    b = bytearray()
    b += bytes(20)                              # song title
    for _ in range(31):                         # 31 sample headers (30 bytes)
        s = bytearray(30)
        s[22:24] = (0).to_bytes(2, "big")       # sample length (words)
        s[25] = 64                              # volume
        b += s
    b += bytes([1])                             # song length
    b += bytes([127])                           # restart byte
    b += bytes(128)                             # pattern order table
    b += b"M.K."                                # 4-channel magic @1080
    b += bytes(1024)                            # one empty pattern (64 rows*4ch*4)
    return bytes(b)


def gen_mod(root):
    seed_dir = os.path.join(root, "seeds", "mod")
    seeds = {
        "seed.it":  _mod_it(),
        "seed.s3m": _mod_s3m(),
        "seed.xm":  _mod_xm(),
        "seed.mod": _mod_protracker(),
    }
    for name, data in seeds.items():
        _write(os.path.join(seed_dir, name), data)

    dict_path = os.path.join(root, "dictionaries", "mod.dict")
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    with open(dict_path, "w") as f:
        f.write("# libmodplug loader signatures\n")
        for tag in ['IMPM', 'SCRM', 'Extended Module: ', 'M.K.', 'M!K!',
                    '4CHN', '6CHN', '8CHN', 'FLT4', 'FLT8',
                    'MTM\\x10', 'if', 'JN', 'DBM0', 'PSM ', 'FAR\\xfe']:
            f.write(f'"{tag}"\n')
    print("  dictionaries/mod.dict written")


# ──────────────────────────────────────────────────
#  Kate-in-Ogg seed (modules/codec/kate.c -> contrib libkate)
# ──────────────────────────────────────────────────
#
# The kate decoder is reached through the ogg demuxer: ogg.c detects a logical
# stream whose first packet is `\x80kate\0\0\0`, emits a VLC_CODEC_KATE SPU ES,
# and feeds the backed-up headers + data packets to codec/kate.c (libkate).
# There is no kate content in the existing ogg corpus, so kate.c + libkate are
# unreached. This seed is therefore written into seeds/ogg/ (the target that
# forces the "ogg" demuxer).
#
# Header layout consumed by ogg.c:Ogg_ReadKateHeader() (all byte-aligned):
#   [0]=0x80  [1:8]="kate\0\0\0"  [8:11]=version  [11]=num_headers
#   [15]=granule_shift  [24:28]=gnum(LE32, must be !=0)  [28:32]=gden(LE32)
#   [32:48]=language  [48:64]=category   -> minimal valid ID header = 64 bytes.

def _kate_id_header(num_headers: int = 2) -> bytes:
    h = bytearray(64)
    h[0] = 0x80
    h[1:8] = b"kate\x00\x00\x00"
    h[8] = 0                                  # bitstream version major
    h[9] = 6                                  # bitstream version minor
    h[11] = num_headers                       # total number of headers
    h[15] = 0                                 # granule shift
    h[24:28] = (1000).to_bytes(4, "little")   # granule rate numerator (!=0)
    h[28:32] = (1000).to_bytes(4, "little")   # granule rate denominator
    h[32:35] = b"und"                         # language
    h[48:57] = b"subtitles"                   # category
    return bytes(h)


def _kate_comment_header() -> bytes:
    # 0x81 + magic + minimal Vorbis-style comment (empty vendor, 0 comments).
    return (b"\x81kate\x00\x00\x00"
            + (0).to_bytes(4, "little")       # vendor length
            + (0).to_bytes(4, "little"))      # user comment count


def _kate_eos_packet() -> bytes:
    # Kate "end of stream" data packet (packet type 0x7F).
    return b"\x7fkate\x00\x00\x00"


def seed_kate_ogg() -> bytes:
    serial = 0x6B617465  # "kate"
    pages = []
    pages.append(ogg_page([_kate_id_header(num_headers=2)],
                          serial=serial, page_seq=0, bos=True))
    pages.append(ogg_page([_kate_comment_header()],
                          serial=serial, page_seq=1))
    pages.append(ogg_page([_kate_eos_packet()],
                          serial=serial, page_seq=2, granule=1, eos=True))
    return b"".join(pages)


def gen_kate(root):
    out = os.path.join(root, "seeds", "ogg")
    os.makedirs(out, exist_ok=True)
    _write(os.path.join(out, "kate_min.ogg"), seed_kate_ogg())


# ──────────────────────────────────────────────────
#  main
# ──────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <fuzz-corpus-root>', file=sys.stderr)
        sys.exit(1)
    root = sys.argv[1]
    os.makedirs(root, exist_ok=True)
    gen_ts(root)
    gen_ps(root)
    gen_heif(root)
    gen_avi(root)
    gen_es(root)
    gen_rawdv(root)
    gen_vc1(root)
    gen_cdg(root)
    gen_mus(root)
    gen_mpgv(root)
    gen_h264(root)
    gen_tta(root)
    gen_caf(root)
    gen_araw(root)
    gen_heif_extra(root)
    gen_ogg(root)
    gen_mkv(root)
    gen_mp4_extras(root)
    gen_cea708(root)
    gen_gme(root)
    gen_mod(root)
    gen_kate(root)


if __name__ == '__main__':
    main()

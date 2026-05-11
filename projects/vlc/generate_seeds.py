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
#   seeds/mus/*.mus           — DOOM-style .MUS music with event variants.
#   dictionaries/{heif,rawdv,vc1,cdg,mus}.dict
#
# Usage:
#     generate_seeds.py <fuzz-corpus-root>

import os
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


def psi_packet(section: bytes, pid: int) -> bytes:
    """Wrap a PSI section in a single TS packet (pointer_field = 0x00)."""
    payload = bytes([0x00]) + section   # pointer_field = 0
    assert len(payload) <= 184, "Section too large for one TS packet"
    return make_ts_packet(pid, payload, pusi=True, cc=0)


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


def pes_ts_packets(pes_data: bytes, pid: int, pcr_90khz: int = None) -> bytes:
    """Split PES data into TS packets.

    If ``pcr_90khz`` is given, the first packet carries an adaptation field
    with that PCR. The TS demuxer's prepcr queue holds back PES blocks until
    a PCR is observed (or 500ms of stream time elapses), so seeds with a
    single PES never reach the decoder unless we provide a PCR explicitly.
    """
    out = b''
    offset = 0
    pusi = True
    cc = 0
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
SCTE27_PAYLOAD = (
    bytes([0xC6,
           0xB0 | ((_SCTE27_SECT_LEN >> 8) & 0x0F),
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


def seed_dvb_subtitle() -> bytes:
    sub_desc = bytes([
        0x59, 0x08,
        0x65, 0x6E, 0x67,
        0x10,
        0x00, 0x01,
        0x00, 0x01,
    ])
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


def seed_scte27() -> bytes:
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x82, SUBS_PID, b''),
    ])
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    scte_pes = make_ts_pes(0xBD, SCTE27_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID) +
            pes_ts_packets(scte_pes, SUBS_PID))


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


def make_atsc_eit(source_id: int = 0x00FF) -> bytes:
    title_segment = bytes([
        0x01,
        0x65, 0x6E, 0x67,
        0x01,
        0x00,
        0x00,
        0x04,
    ]) + b'TEST'
    event = struct.pack('>H', 0xC001)
    event += struct.pack('>I', 1_000_000)
    event += bytes([0xC0, 0x00, 0x00, 0x3C])
    event += bytes([len(title_segment)]) + title_segment
    event += struct.pack('>H', 0xF000)
    body = bytes([0x01]) + event
    return _atsc_section(0xCB, source_id, body)


def seed_atsc_psip() -> bytes:
    ga94 = bytes([0x05, 0x04, 0x47, 0x41, 0x39, 0x34])
    eit_pid = 0x1D00
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
        (0x0000, ATSC_BASE_PID, 0, 0),
        (0x0100, eit_pid, 0, 0),
        (0x0004, ATSC_BASE_PID, 0, 0),
    ])
    stt = make_atsc_stt()
    tvct = make_atsc_tvct()
    eit  = make_atsc_eit()
    video_pes = make_ts_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            psi_packet(mgt, ATSC_BASE_PID) +
            psi_packet(stt, ATSC_BASE_PID) +
            psi_packet(tvct, ATSC_BASE_PID) +
            psi_packet(eit, eit_pid))


TS_SEEDS = {
    'mpeg2_video.ts':  seed_mpeg2_video,
    'h264_video.ts':   seed_h264_video,
    'hevc_video.ts':   seed_hevc_video,
    'mpeg1_audio.ts':  seed_mpeg1_audio,
    'aac_audio.ts':    seed_aac_audio,
    'ac3_audio.ts':    seed_ac3_audio,
    'dts_audio.ts':    seed_dts_audio,
    'dvb_subtitle.ts': seed_dvb_subtitle,
    'scte27.ts':       seed_scte27,
    'with_sdt.ts':     seed_with_sdt,
    'multi_program.ts': seed_multi_program,
    'multi_stream.ts': seed_multi_stream,
    'atsc_psip.ts':    seed_atsc_psip,
}


def gen_ts(root):
    outdir = os.path.join(root, 'seeds', 'ts')
    os.makedirs(outdir, exist_ok=True)
    for filename, generator in TS_SEEDS.items():
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
    _write(os.path.join(root, "seeds/mus/minimal_play.mus"), seed1)

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
    _write(os.path.join(root, "seeds/mus/controls.mus"), seed2)

    dict_path = os.path.join(root, "dictionaries/mus.dict")
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


def _build_h264_cea708_seed() -> bytes:
    # cc_data: process_cc_data_flag=1, reserved=1, cc_count=3.
    process_cc = 0xC0 | 0x03
    cc_data  = bytes([process_cc, 0xFF])
    cc_data += bytes([0xFC, 0x41, 0x80])      # NTSC field 1 — 608 ch 1 'A'
    cc_data += bytes([0xFF, 0x01, 0x21])      # DTVCC packet start
    cc_data += bytes([0xFE, 0x21, 0x41])      # DTVCC packet data

    # user_data_registered_itu_t_t35 (SEI type 4):
    # country=0xB5 + provider=0x0031 + user_id='GA94' + type=0x03 + cc_data + 0xFF
    t35 = bytes([0xB5, 0x00, 0x31]) + b'GA94' + bytes([0x03]) + cc_data + bytes([0xFF])

    sei_payload = bytes([0x04]) + bytes([len(t35)]) + t35 + bytes([0x80])
    sei_nal = bytes([0x06]) + _rbsp(sei_payload)

    sps = bytes([0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8])
    pps = bytes([0x68, 0xCE, 0x38, 0x80])
    idr = bytes([0x65, 0x88, 0x84, 0x00, 0x33, 0xFF])

    sc = b'\x00\x00\x00\x01'
    return sc + sps + sc + pps + sc + sei_nal + sc + idr


def gen_h264(root):
    # Appended to the upstream h264 corpus shipped in vlc-fuzz-corpus.
    _write(os.path.join(root, "seeds/h264/cea708_sei.264"),
           _build_h264_cea708_seed())


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
    gen_rawdv(root)
    gen_vc1(root)
    gen_cdg(root)
    gen_mus(root)
    gen_mpgv(root)
    gen_h264(root)


if __name__ == '__main__':
    main()

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
# Generates minimal but structurally valid MPEG-TS seed files for the
# vlc-demux-dec-libfuzzer-ts fuzzer target.
#
# The existing vlc-fuzz-corpus TS seeds are null-packet-only files (PID=0x1FFF
# filled with 0xFF), which means the TS demuxer never reaches PAT/PMT parsing,
# PES demuxing, or any of the stream-specific processing in ts_psi.c, ts_pes.c,
# ts_pid.c, ts_streams.c, ts_decoders.c, ts_scte.c, ts_arib.c, ts_si.c etc.
# Replacing them with seeds that contain PAT + PMT + PES packets dramatically
# increases reachable code in modules/demux/mpeg/*.
#
# Each generated file is exactly N * 188 bytes (valid TS packet boundaries).

import os
import struct
import sys


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
    # Version 0, current_next=1, section 0/0
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
    body = struct.pack('>H', orig_net) + b'\xFF'  # original_network_id + reserved
    for svc_id, (name, svc_type) in services.items():
        svc_name_bytes = name.encode('utf-8')
        # Service descriptor (tag=0x48)
        desc = bytes([
            0x48,
            3 + len(svc_name_bytes),  # descriptor_length
            svc_type,                  # service_type (0x01=digital TV)
            0x00,                      # service_provider_name_length
            len(svc_name_bytes),       # service_name_length
        ]) + svc_name_bytes
        body += struct.pack('>H', svc_id)
        body += struct.pack('>H', 0x8000 | len(desc))  # running=4, free_CA=0
        body += desc
    # SDT has a different layout for tid_ext (= transport_stream_id)
    section_length = 2 + 1 + 1 + 1 + len(body) + 4
    hdr = bytes([0x42]) + struct.pack('>H', 0xB000 | section_length)
    inner = struct.pack('>H', tsid) + bytes([0xC1, 0x00, 0x00]) + body
    full = hdr + inner
    return full + struct.pack('>I', crc32_mpeg(full))


def make_pes(stream_id: int, payload: bytes, pts_90khz: int = 0) -> bytes:
    """Build a PES packet with optional PTS."""
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
#  Payload fragments
# ──────────────────────────────────────────────────

# Minimal MPEG-2 video ES (seq header + GOP + picture start)
MPGV_PAYLOAD = bytes([
    0x00, 0x00, 0x01, 0xB3, 0x16, 0x00, 0xF0, 0x15,
    0xFF, 0xFF, 0xE0, 0x00,
    0x00, 0x00, 0x01, 0xB8, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0xFF, 0xFF,
    0x00, 0x00, 0x01, 0x01, 0x22, 0x00, 0x00,
])

# Minimal H.264 Annex B: SPS + PPS NAL units
H264_PAYLOAD = bytes([
    # SPS (nal_unit_type=7, profile=66/baseline, level=30)
    0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E,
    0xD9, 0x00, 0xA0, 0x47, 0xFE, 0xC8,
    # PPS (nal_unit_type=8)
    0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80,
    # IDR slice start (nal_unit_type=5, slice_type=I)
    0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00,
    0x33, 0xFF,
])

# Minimal HEVC/H.265 Annex B: VPS + SPS + PPS NAL units
HEVC_PAYLOAD = bytes([
    # VPS (nal_unit_type=32)
    0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C, 0x01,
    0xFF, 0xFF, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
    # SPS (nal_unit_type=33)
    0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01,
    0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00,
    # IDR slice (nal_unit_type=19)
    0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0xAF, 0x09,
])

# Minimal MPEG-1 audio layer 2 (MP2) frame sync + header
MP2_PAYLOAD = bytes([
    0xFF, 0xFD, 0x90, 0x00,  # sync word + MPEG-1 audio, layer 2, 128kbps, 44100Hz, stereo
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Minimal MPEG-1 audio layer 3 (MP3) frame sync
MP3_PAYLOAD = bytes([
    0xFF, 0xFB, 0x90, 0x00,  # MPEG-1, Layer 3, 128kbps, 44.1kHz
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Minimal AAC ADTS frame (2048 byte frame, 44100Hz, 2ch)
AAC_ADTS_PAYLOAD = bytes([
    0xFF, 0xF1, 0x50, 0x80, 0x01, 0x7F, 0xFC,  # ADTS sync + header (LC profile)
    0x00, 0x00,
])

# Minimal AC-3 frame (syncword + header)
AC3_PAYLOAD = bytes([
    0x0B, 0x77,             # AC-3 sync word
    0x00, 0x00,             # CRC1
    0x04, 0x20,             # fscod=0 (48kHz), frmsizecod=4 (96kbps), bsid=1, bsmod=0
    0x00, 0x00, 0x00, 0x00, # padding
])

# Minimal DTS frame (syncword)
DTS_PAYLOAD = bytes([
    0x7F, 0xFE, 0x80, 0x01,  # DTS core sync word
    0xFF, 0x1F, 0x00, 0x00, 0xFF, 0xE8,
])

# DVB subtitle PES payload (ETSI EN 300 743). The previous version was
# 3 bytes (0x20 0x00 0x0F) and immediately failed inside decode_segment(),
# leaving modules/codec/dvbsub.c at <8% line coverage. The build below
# emits a complete subtitle data block exercising every segment dispatch
# branch in decode_segment() (DDS/PCS/RCS/CLUT/ODS/ALT_CLUT/EOD/STUFFING)
# plus the rendering pipeline (render_segments/render_region/render_pdata)
# triggered when PCS state == ACQUISITION sets b_page=true.
def _dvbsub_seg(seg_type: int, page_id: int, data: bytes) -> bytes:
    return bytes([0x0F, seg_type]) + struct.pack('>HH', page_id, len(data)) + data


def _build_dvb_sub_payload(page_id: int = 1) -> bytes:
    out = bytes([0x20, 0x00])  # data_identifier, subtitle_stream_id
    # Display Definition Segment (DDS, 0x14): 720x576, no window
    out += _dvbsub_seg(0x14, page_id,
                       bytes([0x10, 0x02, 0xCF, 0x02, 0x3F]))
    # Page Composition Segment (PCS, 0x10): state=ACQUISITION sets b_page=true
    # 1 region ref (id=0 at (0,0))
    out += _dvbsub_seg(0x10, page_id,
                       bytes([0x05, 0x14,
                              0x00, 0xFF, 0x00, 0x00, 0x00, 0x00]))
    # Region Composition Segment (RCS, 0x11): 16x16 8-bpp region, 1 obj ref
    out += _dvbsub_seg(0x11, page_id,
                       bytes([0x00, 0x10,
                              0x00, 0x10, 0x00, 0x10,
                              0x4C, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    # CLUT Definition Segment (0x12): one entry full_range, one entry 8-bit
    out += _dvbsub_seg(0x12, page_id,
                       bytes([0x00, 0x10,
                              0x00, 0xE1, 0x80, 0x80, 0x80, 0x80,
                              0x01, 0x21, 0xFF, 0x80, 0x80, 0x00]))
    # Object Data Segment (ODS, 0x13) coding_method=0 (pixel data).
    # Top-field bytes exercise dvbsub_pdata2bpp / 4bpp / 8bpp / map tables /
    # end-of-line (0xF0) inside dvbsub_render_pdata().
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
    # ODS coding_method=1 (character string). Reaches the !=0 dispatch arm.
    out += _dvbsub_seg(0x13, page_id,
                       struct.pack('>H', 0x0001) + bytes([0x40])
                       + bytes([0x02])
                       + struct.pack('>HH', 0x0041, 0x0042))
    # Alternative CLUT (0x16): 8-bit YCbCr, SDR-709 colorimetry, 2 entries
    out += _dvbsub_seg(0x16, page_id,
                       bytes([0x01, 0x10, 0x00, 0x00,
                              0x80, 0x80, 0x80, 0x00,
                              0xFF, 0x80, 0x80, 0x00]))
    # Stuffing (0xFF) and End-of-Display (0x80)
    out += _dvbsub_seg(0xFF, page_id, b'\x00\x00')
    out += _dvbsub_seg(0x80, page_id, b'')
    # End-of-PES marker: low 6 bits must be 0x3F (0xFF satisfies)
    out += bytes([0xFF])
    return out


DVB_SUB_PAYLOAD = _build_dvb_sub_payload(page_id=1)

# The TS demuxer (modules/demux/mpeg/ts_pes.c:115) marks PES blocks CORRUPTED
# when i_gathered is more than 16 bytes beyond i_data_size (= PES_packet_length
# + TS_PES_HEADER_SIZE). The "copy" SPU packetizer (modules/packetizer/copy.c
# PacketizeSub) drops corrupted blocks, so the dvbsub decoder never sees them.
# Pad the PES so PES_packet_length closely matches the TS packet's 184-byte
# payload after the 8-byte optional PES header (PTS-only): 184 - 6 - 8 = 170.
_DVB_SUB_PAD_TARGET = 170                               # final PES payload bytes
DVB_SUB_PAYLOAD = DVB_SUB_PAYLOAD + bytes(
    [0xFF] * max(0, _DVB_SUB_PAD_TARGET - len(DVB_SUB_PAYLOAD)))

# SCTE-27 subtitling data (minimal)
SCTE27_PAYLOAD = bytes([
    0x00, 0x01,  # segment_type + ...
    0x00, 0x00, 0x00, 0x00,
])

# ──────────────────────────────────────────────────
#  Seed file generators
# ──────────────────────────────────────────────────

PMT_PID    = 0x0100
VIDEO_PID  = 0x0101
AUDIO_PID  = 0x0102
SUBS_PID   = 0x0103
SDT_PID    = 0x0011   # SDT is on well-known PID 0x0011


def seed_mpeg2_video() -> bytes:
    """PAT + PMT (MPEG-2 video, stream_type=0x02) + one video PES packet."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x02, VIDEO_PID, b'')])
    pes = make_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, VIDEO_PID))


def seed_h264_video() -> bytes:
    """PAT + PMT (H.264/AVC video, stream_type=0x1B) + one H.264 PES packet."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x1B, VIDEO_PID, b'')])
    pes = make_pes(0xE0, H264_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, VIDEO_PID))


def seed_hevc_video() -> bytes:
    """PAT + PMT (HEVC/H.265 video, stream_type=0x24) + one HEVC PES packet."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x24, VIDEO_PID, b'')])
    pes = make_pes(0xE0, HEVC_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, VIDEO_PID))


def seed_mpeg1_audio() -> bytes:
    """PAT + PMT (MPEG-1 audio, stream_type=0x03) + one MP2 PES packet."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x03, AUDIO_PID, b'')])
    pes = make_pes(0xC0, MP2_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_aac_audio() -> bytes:
    """PAT + PMT (AAC, stream_type=0x0F ADTS) + one AAC PES packet."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x0F, AUDIO_PID, b'')])
    pes = make_pes(0xC0, AAC_ADTS_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_ac3_audio() -> bytes:
    """PAT + PMT (private, stream_type=0x06 + AC-3 descriptor) + one AC-3 PES."""
    # AC-3 registration descriptor (0x05) + DTAG=0x6A (AC-3 descriptor)
    ac3_desc = bytes([0x05, 0x04, 0x41, 0x43, 0x2D, 0x33])  # "AC-3" registration
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x06, AUDIO_PID, ac3_desc)])
    pes = make_pes(0xBD, AC3_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_dts_audio() -> bytes:
    """PAT + PMT (private, stream_type=0x06) + one DTS PES packet."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, AUDIO_PID, [(0x06, AUDIO_PID, b'')])
    pes = make_pes(0xBD, DTS_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(pes, AUDIO_PID))


def seed_dvb_subtitle() -> bytes:
    """PAT + PMT (private, DVB subtitle stream_type=0x06 + subtitling descriptor) + PES."""
    # DVB subtitling descriptor (tag=0x59)
    sub_desc = bytes([
        0x59, 0x08,               # tag, length
        0x65, 0x6E, 0x67,         # ISO 639 language = "eng"
        0x10,                     # subtitling_type = 0x10 (DVB normal)
        0x00, 0x01,               # composition_page_id
        0x00, 0x01,               # ancillary_page_id
    ])
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x06, SUBS_PID, sub_desc),
    ])
    # PCR on the video PID (which is the PCR_PID) so the TS demuxer's prepcr
    # queue gets flushed and the dvbsub block is delivered to the decoder.
    # IMPORTANT: VLC_TICK_INVALID == 0, so PTS/DTS must be NONZERO or the
    # spu packetizer (modules/packetizer/copy.c PacketizeSub) drops the block.
    # We emit two DVB sub PES so the second's PUSI=1 also forces the first
    # to drain.
    video_pes = make_pes(0xE0, MPGV_PAYLOAD, pts_90khz=900)
    subs_pes_a = make_pes(0xBD, DVB_SUB_PAYLOAD, pts_90khz=1800)
    subs_pes_b = make_pes(0xBD, DVB_SUB_PAYLOAD, pts_90khz=9000)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID, pcr_90khz=450) +
            pes_ts_packets(subs_pes_a, SUBS_PID) +
            pes_ts_packets(subs_pes_b, SUBS_PID))


def seed_scte27() -> bytes:
    """PAT + PMT with SCTE-27 subtitles (stream_type=0x82) + PES."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID, b''),
        (0x82, SUBS_PID, b''),    # 0x82 = SCTE-27 subtitling
    ])
    video_pes = make_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    scte_pes = make_pes(0xBD, SCTE27_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID) +
            pes_ts_packets(scte_pes, SUBS_PID))


def seed_with_sdt() -> bytes:
    """PAT + PMT + SDT + PES.  Exercises ts_si.c SDT parsing.
    Order matters: SDT PID is registered by PMT callback, so PMT must arrive
    before the SDT packet so the TS demuxer has the PID in its filter.
    """
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [(0x02, VIDEO_PID, b'')])
    sdt = make_sdt(tsid=0x0001, orig_net=0x0001,
                   services={0x0001: ('Test Service', 0x01)})
    video_pes = make_pes(0xE0, MPGV_PAYLOAD, pts_90khz=0)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            psi_packet(sdt, SDT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID))


def seed_multi_program() -> bytes:
    """PAT with two programs, each with their own PMT.  Exercises multi-program TS."""
    PMT2_PID   = 0x0200
    VIDEO2_PID = 0x0201
    pat = make_pat([(0x0001, PMT_PID), (0x0002, PMT2_PID)])
    pmt1 = make_pmt(0x0001, VIDEO_PID,  [(0x02, VIDEO_PID,  b'')])
    pmt2 = make_pmt(0x0002, VIDEO2_PID, [(0x1B, VIDEO2_PID, b'')])
    video1_pes = make_pes(0xE0, MPGV_PAYLOAD,  pts_90khz=0)
    video2_pes = make_pes(0xE0, H264_PAYLOAD,  pts_90khz=0)
    return (psi_packet(pat,  0x0000) +
            psi_packet(pmt1, PMT_PID) +
            psi_packet(pmt2, PMT2_PID) +
            pes_ts_packets(video1_pes, VIDEO_PID) +
            pes_ts_packets(video2_pes, VIDEO2_PID))


def seed_multi_stream() -> bytes:
    """One program with video + audio + subtitle streams.  Exercises multi-ES demux."""
    pat = make_pat([(0x0001, PMT_PID)])
    pmt = make_pmt(0x0001, VIDEO_PID, [
        (0x02, VIDEO_PID,  b''),
        (0x03, AUDIO_PID,  b''),
        (0x06, SUBS_PID,   b''),
    ])
    video_pes = make_pes(0xE0, MPGV_PAYLOAD,  pts_90khz=0)
    audio_pes = make_pes(0xC0, MP2_PAYLOAD,   pts_90khz=900)
    subs_pes  = make_pes(0xBD, DVB_SUB_PAYLOAD, pts_90khz=1800)
    return (psi_packet(pat, 0x0000) +
            psi_packet(pmt, PMT_PID) +
            pes_ts_packets(video_pes, VIDEO_PID) +
            pes_ts_packets(audio_pes, AUDIO_PID) +
            pes_ts_packets(subs_pes,  SUBS_PID))


SEEDS = {
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
}


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <output_directory>', file=sys.stderr)
        sys.exit(1)
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    for filename, generator in SEEDS.items():
        data = generator()
        assert len(data) % 188 == 0, f'{filename}: length {len(data)} not multiple of 188'
        path = os.path.join(outdir, filename)
        with open(path, 'wb') as f:
            f.write(data)
        print(f'  {filename}: {len(data)} bytes ({len(data) // 188} TS packets)')


if __name__ == '__main__':
    main()

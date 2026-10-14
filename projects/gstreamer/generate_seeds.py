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

"""Structured seed generation for the GStreamer OSS-Fuzz fuzz targets.

The fuzz targets in ci/fuzzing each parse a well-defined binary or textual
format, but ship with only a handful of corpus files (2-12 each, and the
push-based `typefind` target has none).  This script emits structurally valid
seeds for each target so the fuzzer starts from inputs that actually reach the
parsing code instead of having to rediscover the container layouts.

Targets and the code they exercise (see the public summary.json for the
weakly-covered files):

  gst-codec-utils  pbutils/codec-utils.c   H.264/H.265/H.266 profile-tier-level,
                                           AV1 av1C, Opus header parsing
  gst-tag          gst/tag/*.c             ID3v1/ID3v2 frames, EXIF IFD, XMP,
                                           Vorbis comments
  gst-subparse     subparse element        SubRip, WebVTT, MicroDVD, SubViewer,
                                           MPL2, SAMI, TMPlayer, LRC
  typefind         gst/typefind + plugins  magic-based type detection for many
                                           container/codec formats
  gst-discoverer   ogg/theora/vorbis       (kept minimal -- needs real media)

Each format is emitted into a per-target subdirectory:
    <outdir>/<target>/<name>
so the build script can zip each subdirectory into the matching
<target>_seed_corpus.zip.

Only the Python standard library is used.

Usage:  python3 generate_seeds.py <output_dir>
"""

import os
import sys
import shutil
import struct
import zlib


def w(d, name, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("latin-1"))


# ==========================================================================
# gst-codec-utils
# ==========================================================================
def gen_codec_utils(base):
    d = os.path.join(base, "gst-codec-utils")

    # --- H.264: codec_data is read as [profile_idc, constraints, level_idc].
    # AVCDecoderConfigurationRecord (as carried in MP4 'avcC').
    for name, prof, lvl in [("baseline", 66, 30), ("main", 77, 31),
                            ("high", 100, 40), ("high10", 110, 50),
                            ("high422", 122, 51), ("high444", 244, 52)]:
        sps = bytes([0x67, prof, 0x00, lvl, 0xAC, 0xB2, 0x00, 0x07])
        pps = bytes([0x68, 0xCE, 0x3C, 0x80])
        avcc = bytes([0x01, prof, 0x00, lvl, 0xFF, 0xE1]) + \
            struct.pack(">H", len(sps)) + sps + b"\x01" + \
            struct.pack(">H", len(pps)) + pps
        w(d, "h264_avcc_%s.bin" % name, avcc)
        # the bare 3-byte profile/flags/level slice too
        w(d, "h264_ptl_%s.bin" % name, bytes([prof, 0x00, lvl]))

    # --- H.265 profile_tier_level (12 bytes minimum to set level too).
    def hevc_ptl(profile_idc, tier, level_idc, compat_bit=1):
        b = bytearray(12)
        b[0] = (profile_idc & 0x1f)          # space=0 tier=0 profile_idc
        if tier:
            b[0] |= 0x20
        # general_profile_compatibility_flags (32 bits) at bytes 1..4
        compat = 1 << (31 - compat_bit)
        b[1:5] = struct.pack(">I", compat)
        # constraint flags bytes 5..10 (leave general_progressive etc set)
        b[5] = 0x90
        b[11] = level_idc                    # general_level_idc
        return bytes(b)
    # A few profile/tier/level variants. (Empirically the harness's h264/h265
    # profile helpers extract fields without per-value line branches, so a
    # larger matrix adds ~no coverage -- keep this set small.)
    for name, p, t, l in [("main", 1, 0, 120), ("main10", 2, 0, 123),
                          ("main_still", 3, 0, 90), ("high_tier", 1, 1, 150),
                          ("rext4", 4, 0, 153)]:
        w(d, "h265_ptl_%s.bin" % name, hevc_ptl(p, t, l))

    # --- H.266/VVC profile_tier_level-ish payload.
    for name, byte0, lvl in [("main10", 0x01, 51), ("main10_444", 0x21, 67)]:
        w(d, "h266_ptl_%s.bin" % name,
          bytes([byte0, 0x00, 0x00, 0x00, lvl, 0x00, 0x00, 0x00]))

    # --- AV1 codec configuration record (av1C).
    # marker(1)=1 version(7)=1 -> 0x81 ; seq_profile(3) seq_level_idx(5)
    for name, prof, lvl in [("main_l30", 0, 1), ("high_l40", 1, 8),
                            ("pro_l50", 2, 16)]:
        seqhdr = bytes([0x0A, 0x0B, 0x00, 0x00, 0x00, 0x24, 0xCF, 0xBF,
                        0x1B, 0xE0, 0x01, 0x40])  # tiny OBU_SEQUENCE_HEADER
        av1c = bytes([0x81, (prof << 5) | lvl, 0x00, 0x00]) + seqhdr
        w(d, "av1c_%s.bin" % name, av1c)

    # --- Opus header tail (harness prepends "OpusHead\x01").
    # layout after version: channels(1) pre_skip(2) rate(4) gain(2) mapping(1)
    for name, ch, family in [("mono", 1, 0), ("stereo", 2, 0),
                             ("surround", 6, 1)]:
        tail = bytes([ch]) + struct.pack("<H", 312) + \
            struct.pack("<I", 48000) + struct.pack("<h", 0) + bytes([family])
        if family == 1:
            tail += bytes([ch, ch - 1]) + bytes(range(ch))  # stream/coupled/map
        w(d, "opus_tail_%s.bin" % name, tail)


# ==========================================================================
# gst-tag
# ==========================================================================
def _id3v2_frame(fid, data, version=4):
    if isinstance(data, str):
        data = data.encode("latin-1")
    if version == 4:                      # synchsafe size
        sz = bytes([(len(data) >> 21) & 0x7f, (len(data) >> 14) & 0x7f,
                    (len(data) >> 7) & 0x7f, len(data) & 0x7f])
    else:                                 # 2.3 plain size
        sz = struct.pack(">I", len(data))
    return fid + sz + b"\x00\x00" + data


def _id3v2_tag(frames, version=4):
    body = b"".join(frames)
    size = len(body)
    ssize = bytes([(size >> 21) & 0x7f, (size >> 14) & 0x7f,
                   (size >> 7) & 0x7f, size & 0x7f])
    return b"ID3" + bytes([version, 0, 0]) + ssize + body


def _tiff_exif_multi():
    """A TIFF/EXIF buffer with IFD0 + an Exif sub-IFD (0x8769) + a GPS sub-IFD
    (0x8825), little-endian, covering ~all tags gstexiftag.c maps so each tag's
    deserializer branch runs.  Layout: 8-byte TIFF header, then the three IFDs
    laid out back-to-back, with all out-of-line values in a trailing data
    area.  Types: 2=ASCII 3=SHORT 4=LONG 5=RATIONAL 7=UNDEFINED 10=SRATIONAL."""
    import struct as _s
    HDR = 8

    def build_ifd(entries, ifd_offset, next_off=0):
        # entries: list of (tag, typ, count, raw_value_bytes_or_inline)
        n = len(entries)
        ifd_size = 2 + n * 12 + 4
        data_off = ifd_offset + ifd_size
        body = _s.pack("<H", n)
        tail = b""
        for tag, typ, count, val in entries:
            if len(val) <= 4:
                vfield = val.ljust(4, b"\x00")
            else:
                vfield = _s.pack("<I", data_off + len(tail))
                tail += val
                if len(tail) % 2:
                    tail += b"\x00"
            body += _s.pack("<HHI", tag, typ, count) + vfield
        body += _s.pack("<I", next_off)
        return body + tail, ifd_size + len(tail)

    def rat(num, den):
        return _s.pack("<II", num, den)

    def srat(num, den):
        return _s.pack("<ii", num, den)

    # --- main IFD0 entries (placeholders for the two sub-IFD pointers) ---
    ifd0 = [
        (0x10E, 2, 0, b"a scene\x00"),                  # ImageDescription
        (0x10F, 2, 0, b"SeedCam\x00"),                  # Make
        (0x110, 2, 0, b"Model 9000\x00"),               # Model
        (0x112, 3, 1, _s.pack("<H", 6)),                # Orientation
        (0x11A, 5, 1, rat(72, 1)),                      # XResolution
        (0x11B, 5, 1, rat(72, 1)),                      # YResolution
        (0x128, 3, 1, _s.pack("<H", 2)),                # ResolutionUnit
        (0x131, 2, 0, b"seedsw 1.0\x00"),               # Software
        (0x132, 2, 20, b"2026:06:12 03:04:05\x00"),     # DateTime
        (0x13B, 2, 0, b"An Artist\x00"),                # Artist
        (0x8298, 2, 0, b"(c) nobody\x00"),              # Copyright
    ]
    # --- Exif sub-IFD ---
    exififd = [
        (0x829A, 5, 1, rat(1, 125)),                    # ExposureTime
        (0x829D, 5, 1, rat(28, 10)),                    # FNumber
        (0x8822, 3, 1, _s.pack("<H", 2)),               # ExposureProgram
        (0x8827, 3, 1, _s.pack("<H", 400)),             # PhotographicSensitivity
        (0x8830, 3, 1, _s.pack("<H", 1)),               # SensitivityType
        (0x8833, 4, 1, _s.pack("<I", 400)),             # ISOSpeed
        (0x9003, 2, 20, b"2026:06:12 03:04:05\x00"),    # DateTimeOriginal
        (0x9004, 2, 20, b"2026:06:12 03:04:05\x00"),    # DateTimeDigitized
        (0x9201, 10, 1, srat(7, 1)),                    # ShutterSpeedValue
        (0x9202, 5, 1, rat(3, 1)),                      # ApertureValue
        (0x9204, 10, 1, srat(-1, 3)),                   # ExposureBias
        (0x9207, 3, 1, _s.pack("<H", 5)),               # MeteringMode
        (0x9208, 3, 1, _s.pack("<H", 1)),               # LightSource
        (0x9209, 3, 1, _s.pack("<H", 0x19)),            # Flash
        (0x920A, 5, 1, rat(35, 1)),                     # FocalLength
        (0x927C, 7, 4, b"\x01\x02\x03\x04"),            # MakerNote
        (0xA300, 7, 1, b"\x03"),                        # FileSource
        (0xA301, 7, 1, b"\x01"),                        # SceneType
        (0xA402, 3, 1, _s.pack("<H", 0)),               # ExposureMode
        (0xA403, 3, 1, _s.pack("<H", 1)),               # WhiteBalance
        (0xA404, 5, 1, rat(2, 1)),                      # DigitalZoomRatio
        (0xA406, 3, 1, _s.pack("<H", 1)),               # SceneCaptureType
        (0xA407, 3, 1, _s.pack("<H", 1)),               # GainControl
        (0xA408, 3, 1, _s.pack("<H", 1)),               # Contrast
        (0xA409, 3, 1, _s.pack("<H", 1)),               # Saturation
        (0xA40A, 3, 1, _s.pack("<H", 1)),               # Sharpness
    ]
    # --- GPS sub-IFD ---
    gpsifd = [
        (0x1, 2, 2, b"N\x00"),                          # GPSLatitudeRef
        (0x2, 5, 3, rat(51, 1) + rat(30, 1) + rat(0, 1)),   # GPSLatitude
        (0x3, 2, 2, b"W\x00"),                          # GPSLongitudeRef
        (0x4, 5, 3, rat(0, 1) + rat(7, 1) + rat(0, 1)),     # GPSLongitude
        (0x5, 1, 1, b"\x00"),                           # GPSAltitudeRef
        (0x6, 5, 1, rat(100, 1)),                       # GPSAltitude
        (0xC, 2, 2, b"K\x00"),                          # GPSSpeedRef
        (0xD, 5, 1, rat(50, 1)),                        # GPSSpeed
        (0xE, 2, 2, b"T\x00"),                          # GPSTrackRef
        (0xF, 5, 1, rat(90, 1)),                        # GPSTrack
        (0x10, 2, 2, b"T\x00"),                         # GPSImgDirectionRef
        (0x11, 5, 1, rat(180, 1)),                      # GPSImgDirection
        (0x1F, 5, 1, rat(5, 1)),                        # GPSHPositioningError
    ]
    # Lay out IFD0, then Exif IFD, then GPS IFD sequentially.
    # First compute IFD0 size with the two pointer entries appended.
    ifd0_n = len(ifd0) + 2
    ifd0_size = 2 + ifd0_n * 12 + 4
    # rough sizes to compute offsets (each tail value placed after its IFD)
    blob0, sz0 = build_ifd(ifd0 + [
        (0x8769, 4, 1, _s.pack("<I", 0)),               # placeholder
        (0x8825, 4, 1, _s.pack("<I", 0)),               # placeholder
    ], HDR)
    exif_off = HDR + sz0
    blobE, szE = build_ifd(exififd, exif_off)
    gps_off = exif_off + szE
    blobG, szG = build_ifd(gpsifd, gps_off)
    # rebuild IFD0 with real pointer values
    blob0, sz0 = build_ifd(ifd0 + [
        (0x8769, 4, 1, _s.pack("<I", exif_off)),
        (0x8825, 4, 1, _s.pack("<I", gps_off)),
    ], HDR)
    tiff = b"II*\x00" + _s.pack("<I", HDR) + blob0 + blobE + blobG
    return tiff


def gen_tag(base):
    d = os.path.join(base, "gst-tag")

    # --- ID3v2.4 with a broad set of frame types.
    text = b"\x03"        # encoding = UTF-8
    frames = [
        _id3v2_frame(b"TIT2", text + b"A Fuzzed Title"),
        _id3v2_frame(b"TPE1", text + b"The Artist"),
        _id3v2_frame(b"TALB", text + b"An Album"),
        _id3v2_frame(b"TRCK", text + b"3/12"),
        _id3v2_frame(b"TYER", text + b"2026"),
        _id3v2_frame(b"TCON", text + b"(17)Rock"),
        _id3v2_frame(b"TBPM", text + b"128"),
        _id3v2_frame(b"COMM", text + b"eng\x00short comment"),
        _id3v2_frame(b"TXXX", text + b"replaygain_track_gain\x00-3.5 dB"),
        _id3v2_frame(b"WXXX", b"\x00desc\x00http://example.com"),
        _id3v2_frame(b"USLT", text + b"eng\x00\x00lyric line one\nline two"),
        _id3v2_frame(b"PRIV", b"owner@id\x00\x01\x02\x03\x04"),
        _id3v2_frame(b"UFID", b"http://id\x00\xde\xad\xbe\xef"),
        _id3v2_frame(b"APIC", text + b"image/png\x00\x03cover\x00" +
                     b"\x89PNG\r\n\x1a\n" + b"\x00" * 16),
        _id3v2_frame(b"GEOB", text + b"application/x\x00file.bin\x00obj\x00" +
                     b"\x00" * 8),
        # frames with dedicated handlers not yet covered:
        _id3v2_frame(b"WOAF", b"http://official.example.com/audio"),  # URL link
        _id3v2_frame(b"WCOP", b"http://example.com/copyright"),       # URL link
        _id3v2_frame(b"TDAT", text + b"1206"),         # obsolete date (DDMM)
        _id3v2_frame(b"TIME", text + b"0304"),         # obsolete time (HHMM)
        _id3v2_frame(b"TYER", text + b"2026"),         # obsolete year
        _id3v2_frame(b"TORY", text + b"2025"),         # original release year
        # RVA2: identification\0, then channel(1)+volume(2)+peakbits(1)+peak
        _id3v2_frame(b"RVA2", b"norm\x00\x01\x00\x80\x10\xff\xff"),
        _id3v2_frame(b"POPM", b"user@example.com\x00\xc8" + b"\x00\x00\x00\x05"),
        _id3v2_frame(b"PCNT", b"\x00\x00\x00\x2a"),
        _id3v2_frame(b"MCDI", b"\x00" * 8),
        _id3v2_frame(b"TLAN", text + b"eng"),
        _id3v2_frame(b"TSSE", text + b"seed encoder"),
        # multi-value text frame -> parse_split_strings
        _id3v2_frame(b"TPE1", text + b"Artist A\x00Artist B\x00Artist C"),
    ]
    w(d, "id3v2_4_full.bin", _id3v2_tag(frames, 4))

    # --- ID3v2.3 variant.
    frames3 = [
        _id3v2_frame(b"TIT2", b"\x00Title v23", 3),
        _id3v2_frame(b"TPE1", b"\x01\xff\xfeA\x00r\x00t\x00", 3),  # UTF-16
        _id3v2_frame(b"APIC", b"\x00image/jpeg\x00\x03\x00" + b"\xff\xd8" * 4,
                     3),
    ]
    w(d, "id3v2_3.bin", _id3v2_tag(frames3, 3))

    # --- ID3v1 (exactly 128 bytes).
    v1 = b"TAG" + b"Title".ljust(30, b"\x00") + b"Artist".ljust(30, b"\x00") \
        + b"Album".ljust(30, b"\x00") + b"2026" \
        + b"Comment".ljust(28, b"\x00") + b"\x00" + b"\x03" + bytes([17])
    w(d, "id3v1.bin", v1)

    # --- EXIF with a TIFF header (little-endian) + an IFD of common tags.
    def tiff_exif():
        entries = [
            (0x010F, 2, b"Make\x00"),         # Make (ASCII)
            (0x0110, 2, b"Model XYZ\x00"),    # Model
            (0x0112, 3, struct.pack("<H", 1)),  # Orientation (SHORT)
            (0x011A, 5, struct.pack("<II", 72, 1)),  # XResolution (RATIONAL)
            (0x0131, 2, b"fuzz\x00"),         # Software
            (0x8298, 2, b"(c) nobody\x00"),   # Copyright
        ]
        # Build IFD. RATIONAL/long strings go to an out-of-line area.
        n = len(entries)
        ifd = struct.pack("<H", n)
        # data area starts after IFD (8 header + 2 count + n*12 + 4 next)
        data_off = 8 + 2 + n * 12 + 4
        tail = b""
        for tag, typ, val in entries:
            if typ == 2:        # ASCII
                count = len(val)
            elif typ == 3:      # SHORT
                count = len(val) // 2
            elif typ == 5:      # RATIONAL
                count = len(val) // 8
            else:
                count = len(val)
            if len(val) <= 4:
                valfield = val.ljust(4, b"\x00")
            else:
                valfield = struct.pack("<I", data_off + len(tail))
                tail += val
            ifd += struct.pack("<HHI", tag, typ, count) + valfield
        ifd += struct.pack("<I", 0)   # next IFD = 0
        return b"II*\x00" + struct.pack("<I", 8) + ifd + tail
    w(d, "exif_tiff.bin", tiff_exif())
    # raw IFD without TIFF header (for gst_tag_list_from_exif_buffer)
    w(d, "exif_ifd_le.bin", tiff_exif()[8:])
    # comprehensive multi-IFD EXIF (main + Exif sub-IFD + GPS sub-IFD): hits
    # the per-tag deserializers across gstexiftag.c.
    w(d, "exif_full.bin", _tiff_exif_multi())

    # --- XMP packet.
    xmp = (
        '<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about="" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Fuzz Title'
        '</rdf:li></rdf:Alt></dc:title>'
        '<dc:creator><rdf:Seq><rdf:li>An Author</rdf:li></rdf:Seq>'
        '</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>'
        '<?xpacket end="r"?>')
    w(d, "xmp.bin", xmp.encode("utf-8"))

    # --- Vorbis comment buffer.
    def vorbiscomment():
        vendor = b"fuzz libVorbis"
        comments = [b"TITLE=Vorbis Title", b"VERSION=remaster",
                    b"ARTIST=Vorbis Artist", b"PERFORMER=The Performer",
                    b"ALBUM=Album", b"DATE=2026-06-12", b"GENRE=Electronic",
                    b"TRACKNUMBER=4", b"TRACKTOTAL=12", b"DISCNUMBER=1",
                    b"COPYRIGHT=(c) 2026", b"LICENSE=CC-BY",
                    b"ORGANIZATION=Label", b"DESCRIPTION=a track",
                    b"LOCATION=Studio", b"CONTACT=info@example.com",
                    b"ISRC=US-XXX-26-00001", b"COMPOSER=A Composer",
                    b"REPLAYGAIN_TRACK_GAIN=-2.1 dB",
                    b"REPLAYGAIN_TRACK_PEAK=0.98",
                    b"REPLAYGAIN_ALBUM_GAIN=-1.5 dB",
                    b"REPLAYGAIN_ALBUM_PEAK=0.99",
                    b"MUSICBRAINZ_TRACKID=abc-123",
                    b"MUSICBRAINZ_ARTISTID=def-456",
                    b"BPM=128", b"LANGUAGE=eng",
                    b"METADATA_BLOCK_PICTURE=AAAAAA=="]
        out = struct.pack("<I", len(vendor)) + vendor
        out += struct.pack("<I", len(comments))
        for c in comments:
            out += struct.pack("<I", len(c)) + c
        return out
    w(d, "vorbiscomment.bin", vorbiscomment())


# ==========================================================================
# gst-subparse  (subtitle text formats)
# ==========================================================================
def gen_subparse(base):
    d = os.path.join(base, "gst-subparse")
    w(d, "subrip.srt",
      "1\n00:00:01,000 --> 00:00:04,000\nHello <b>bold</b> world\n\n"
      "2\n00:00:05,500 --> 00:00:08,250\nSecond line\nwith two rows\n\n"
      "3\n00:01:02,100 --> 00:01:05,000\n<i>italic</i> {\\an8}top\n")
    w(d, "webvtt.vtt",
      "WEBVTT - Some title\n\nNOTE a comment\n\n"
      "1\n00:00:00.000 --> 00:00:02.000 line:0 position:50%\n"
      "<v Speaker>Hello</v>\n\n"
      "00:00:02.000 --> 00:00:04.000\n<c.classname>styled</c> text\n")
    w(d, "microdvd.sub",
      "{1}{1}29.970\n{0}{60}First subtitle|second row\n"
      "{75}{120}{y:i}Italic line\n{150}{200}Another\n")
    w(d, "subviewer.sub",
      "[INFORMATION]\n[TITLE]Fuzz\n[END INFORMATION]\n"
      "00:00:01.00,00:00:03.00\nFirst caption\n\n"
      "00:00:04.00,00:00:06.00\nSecond caption\n")
    w(d, "mpl2.txt",
      "[10][30]First mpl2 line\n[35][60]Second line|next row\n")
    w(d, "sami.smi",
      "<SAMI><HEAD><TITLE>Fuzz</TITLE>"
      "<STYLE TYPE=\"text/css\"><!-- P {color:white;} --></STYLE></HEAD>"
      "<BODY><SYNC Start=0><P Class=ENCC>First</P>"
      "<SYNC Start=2000><P Class=ENCC>Second</P></BODY></SAMI>\n")
    w(d, "tmplayer.txt",
      "00:00:01:First TMPlayer line\n00:00:04:Second line\n")
    w(d, "lrc.lrc",
      "[ti:Song]\n[ar:Artist]\n[00:01.00]First lyric\n[00:04.50]Second\n")
    w(d, "qttext.txt",
      "{QTtext}{font:Geneva}{size:12}\n[00:00:01.00]\nFirst caption\n")


# ==========================================================================
# typefind  (push-based type detection -- only the leading magic matters)
# ==========================================================================
def _png():
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + \
            struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + \
        chunk(b"IEND", b"")


def _riff_wav():
    fmt = struct.pack("<HHIIHH", 1, 2, 44100, 176400, 4, 16)
    data = b"\x00" * 32
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + \
        b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _avi():
    body = b"AVI " + b"LIST" + struct.pack("<I", 4) + b"hdrl"
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _isobmff(brand):
    ftyp = b"ftyp" + brand + struct.pack(">I", 0x200) + brand + b"mp42"
    ftyp = struct.pack(">I", len(ftyp) + 4) + ftyp
    mdat = struct.pack(">I", 16) + b"mdat" + b"\x00" * 8
    return ftyp + mdat


def _matroska():
    # EBML header declaring a Matroska/WebM doctype.
    def vint(n):
        return bytes([0x80 | n])
    ebml = (b"\x1aE\xdf\xa3")  # EBML id
    doctype = b"\x42\x82" + vint(8) + b"matroska"
    body = (b"\x42\x86" + vint(1) + b"\x01" +   # EBMLVersion
            b"\x42\xf7" + vint(1) + b"\x01" +   # EBMLReadVersion
            doctype +
            b"\x42\x87" + vint(1) + b"\x02" +   # DocTypeVersion
            b"\x42\x85" + vint(1) + b"\x02")    # DocTypeReadVersion
    hdr = ebml + vint(len(body)) + body
    # a Segment id so demux start is plausible
    seg = b"\x18\x53\x80\x67" + b"\x01\x00\x00\x00\x00\x00\x10\x00"
    return hdr + seg + b"\x00" * 16


def _ogg():
    # OggS page header (version 0, BOS) + a vorbis id header start.
    hdr = b"OggS" + bytes([0, 0x02]) + b"\x00" * 8 + b"\x00" * 4 + \
        struct.pack("<I", 0) + struct.pack("<I", 0) + bytes([1, 30])
    vorbis = b"\x01vorbis" + struct.pack("<I", 0) + bytes([2]) + \
        struct.pack("<I", 44100) + b"\x00" * 16
    return hdr + vorbis


def _flac():
    streaminfo = struct.pack(">I", 0x00000022) + b"\x10\x00\x10\x00" + \
        b"\x00\x00\x00" + b"\x00\x00\x00" + b"\x0a\xc4\x42\xf0" + b"\x00" * 16
    return b"fLaC" + streaminfo


def _mp3_id3():
    # MPEG-1 Layer III, 128 kbit/s, 44.1 kHz -> frame length 417 bytes.
    # The typefinder requires GST_MP3_TYPEFIND_MIN_HEADERS (2) consecutive
    # consistent frames, so emit several so the frame-scan loop confirms.
    frame = b"\xff\xfb\x90\x00" + b"\x00" * 413
    return _id3v2_tag([_id3v2_frame(b"TIT2", b"\x00mp3")], 4) + frame * 6


def _adts_aac():
    # ADTS, AAC-LC, 44.1 kHz, stereo; aac_frame_length = 32 bytes per frame.
    # Repeat so the ADTS frame-walk confirms instead of bailing after one.
    fl = 32
    hdr = bytes([0xFF, 0xF1, 0x50, 0x80 | ((fl >> 11) & 3),
                 (fl >> 3) & 0xFF, ((fl & 7) << 5) | 0x1F, 0xFC])
    return (hdr + b"\x00" * (fl - len(hdr))) * 6


def _mpegts():
    # 12 transport packets of 188 bytes, sync 0x47; first is the PAT (PID 0).
    # mpeg_ts typefind needs >= 4 sync bytes spaced by a valid packet size.
    pat = bytes([0x47, 0x40, 0x00, 0x10, 0x00]) + bytes([0x00, 0xB0, 0x0D,
                 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xF0, 0x00])
    pat = pat.ljust(188, b"\xff"[0:1] * 0 or b"\xff")
    null = bytes([0x47, 0x1F, 0xFF, 0x10]) + b"\x00" * 184
    return pat + null * 11


def _quicktime_full():
    # ftyp + moov (with mvhd) + mdat -> have_moov && have_mdat confirms,
    # and the atom-walk loop runs over several nested atoms.
    def atom(typ, payload=b""):
        return struct.pack(">I", 8 + len(payload)) + typ + payload
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0x200) + b"qt  ")
    mvhd = atom(b"mvhd", b"\x00" * 100)
    tkhd = atom(b"tkhd", b"\x00" * 84)
    trak = atom(b"trak", tkhd)
    moov = atom(b"moov", mvhd + trak)
    mdat = atom(b"mdat", b"\x00" * 32)
    return ftyp + moov + mdat


def gen_typefind(base):
    d = os.path.join(base, "typefind")
    w(d, "png.png", _png())
    w(d, "jpeg.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00" +
      b"\x00" * 16 + b"\xff\xd9")
    w(d, "gif.gif", b"GIF89a" + struct.pack("<HH", 1, 1) +
      b"\x80\x00\x00" + b"\x00\x00\x00\xff\xff\xff" +
      b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
    w(d, "bmp.bmp", b"BM" + struct.pack("<I", 70) + b"\x00\x00\x00\x00" +
      struct.pack("<I", 54) + b"\x00" * 40)
    w(d, "webp.webp", b"RIFF" + struct.pack("<I", 20) + b"WEBPVP8 " +
      struct.pack("<I", 8) + b"\x00" * 8)
    w(d, "wav.wav", _riff_wav())
    w(d, "avi.avi", _avi())
    w(d, "mp4.mp4", _isobmff(b"isom"))
    w(d, "mov.mov", _isobmff(b"qt  "))
    w(d, "heic.heic", _isobmff(b"heic"))
    w(d, "matroska.mkv", _matroska())
    w(d, "ogg.ogg", _ogg())
    w(d, "flac.flac", _flac())
    w(d, "mp3.mp3", _mp3_id3())
    w(d, "aac.aac", _adts_aac())
    w(d, "wavpack.wv", b"wvpk" + struct.pack("<I", 32) + b"\x00" * 32)
    w(d, "ape.ape", b"MAC " + b"\x96\x0f" + b"\x00" * 32)
    w(d, "au.au", b".snd" + struct.pack(">IIIII", 24, 16, 1, 8000, 1))
    w(d, "midi.mid", b"MThd" + struct.pack(">IHHH", 6, 0, 1, 96) +
      b"MTrk" + struct.pack(">I", 4) + b"\x00\xff\x2f\x00")
    w(d, "flv.flv", b"FLV\x01\x05" + struct.pack(">I", 9) +
      struct.pack(">I", 0) + b"\x00" * 16)
    w(d, "mpegts.ts", _mpegts())
    w(d, "quicktime_full.mov", _quicktime_full())
    w(d, "mpeg_ps.mpg", b"\x00\x00\x01\xba" + b"\x44\x00\x04\x00\x04\x01" +
      b"\x00\x03\xf8" + b"\x00\x00\x01\xbb" + b"\x00" * 16)
    w(d, "h264.h264", b"\x00\x00\x00\x01\x67\x42\x00\x1f" + b"\x00" * 8 +
      b"\x00\x00\x00\x01\x68\xce\x3c\x80")
    w(d, "caf.caf", b"caff\x00\x01\x00\x00" + b"\x00" * 16)
    w(d, "ico.ico", b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00" + b"\x00" * 16)
    w(d, "tiff.tiff", b"II*\x00" + struct.pack("<I", 8) +
      struct.pack("<H", 0) + struct.pack("<I", 0))
    w(d, "xml.xml", b"<?xml version=\"1.0\"?><root><a/></root>")
    w(d, "html.html", b"<!DOCTYPE html><html><head></head><body></body></html>")
    w(d, "svg.svg", b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/"
      b"2000/svg\" width=\"1\" height=\"1\"></svg>")
    w(d, "bzip2.bz2", b"BZh91AY&SY" + b"\x00" * 16)
    w(d, "gzip.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 16)
    w(d, "zip.zip", b"PK\x03\x04\x14\x00" + b"\x00" * 26)
    w(d, "elf.bin", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 16)
    w(d, "utf8text.txt", b"plain ascii then unicode \xc3\xa9\xc3\xa8 text\n")

    pad = b"\x00" * 64

    # ---- ISO-BMFF brand variants (distinct quicktime/mj2/3gp/heif paths) ----
    w(d, "mj2.mj2", _isobmff(b"mjp2"))
    w(d, "3gp.3gp", _isobmff(b"3gp4"))
    w(d, "avif.avif", _isobmff(b"avif"))
    w(d, "m4a.m4a", _isobmff(b"M4A "))
    # bare QuickTime atoms (no ftyp): moov-first / mdat-first / wide / free
    for atom in (b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot"):
        w(d, "qt_%s.mov" % atom.decode(), struct.pack(">I", 16) + atom + pad)

    # ---- RIFF / IFF family ----
    def iff(form):
        body = form + pad
        return b"FORM" + struct.pack(">I", len(body)) + body
    w(d, "aiff.aiff", iff(b"AIFF"))
    w(d, "aifc.aifc", iff(b"AIFC"))
    w(d, "iff_8svx.iff", iff(b"8SVX"))
    w(d, "iff_16sv.iff", iff(b"16SV"))
    w(d, "iff_ilbm.iff", iff(b"ILBM"))

    # ---- container / stream formats by leading magic ----
    table = {
        # audio
        "aac_adif.aac": b"ADIF" + pad,
        "shorten.shn": b"ajkg" + b"\x02" + pad,
        "ape_tag.apetag": b"APETAGEX" + struct.pack("<I", 2000) + pad,
        "musepack_sv8.mpc": b"MPCK" + pad,
        "musepack_sv7.mpc": b"MP+" + b"\x07" + pad,
        "dsf.dsf": b"DSD " + struct.pack("<I", 28) + pad,
        "tta.tta": b"TTA1" + pad,
        "ircam.sf": b"\x64\xa3\x00\x00" + pad,
        "w64.w64": b"riff" + b"\x2e\x91\xcf\x11\xa5\xd6\x28\xdb"
                   b"\x04\xc1\x00\x00" + pad,
        "rf64.wav": b"RF64" + struct.pack("<I", 0xffffffff) + b"WAVE" + pad,
        "voc.voc": b"Creative Voice File\x1a" + pad,
        # midi-ish
        "smaf.mmf": b"MMMD" + pad,
        "mobile_xmf.mxmf": b"XMF_" + pad,
        "rmid.rmi": b"RIFF" + struct.pack("<I", 20) + b"RMIDdata" + pad,
        # video / containers
        "dirac.drc": b"BBCD" + pad,
        "nuv.nuv": b"NuppelVideo\x00" + pad,
        "mythtv.nuv": b"MythTVVideo" + pad,
        "nsv.nsv": b"NSVf" + pad,
        "realmedia.rm": b".RMF" + struct.pack(">I", 18) + pad,
        "asf.asf": b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa"
                   b"\x00\x62\xce\x6c" + pad,
        "swf.swf": b"FWS\x09" + struct.pack("<I", 100) + pad,
        "swf_c.swf": b"CWS\x09" + struct.pack("<I", 100) + pad,
        "mxf.mxf": b"\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02\x01"
                   b"\x01\x02\x00\x00" + pad,
        "nut.nut": b"nut/multimedia container\x00" + pad,
        "ipmovie.mve": b"Interplay MVE File\x1a\x00" + pad,
        "yuv4mpeg.y4m": b"YUV4MPEG2 W1 H1 F25:1 Ip A1:1 C420\n" + pad,
        "vivo.viv": b"\x00Version:Vivo/" + pad,
        "fli.fli": b"\x00\x00\x00\x00\x11\xaf" + pad,
        "flc.flc": b"\x00\x00\x00\x00\x12\xaf" + pad,
        "gif87.gif": b"GIF87a" + b"\x01\x00\x01\x00\x00\x00\x00;",
        # images
        "jp2.jp2": b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a" + b"ftypjp2 " + pad,
        "jpc.j2c": b"\xff\x4f\xff\x51" + pad,
        "exr.exr": b"\x76\x2f\x31\x01\x02\x00\x00\x00" + pad,
        "cur.cur": b"\x00\x00\x02\x00\x01\x00\x10\x10\x00\x00" + pad,
        "wbmp.wbmp": b"\x00\x00\x01\x01" + b"\xff" * 8,
        "degas.pi1": b"\x00\x00" + b"\x00" * 32034,
        "pbm.pbm": b"P1\n1 1\n0\n",
        "pgm.pgm": b"P2\n1 1\n255\n0\n",
        "ppm.ppm": b"P3\n1 1\n255\n0 0 0\n",
        "pbm_raw.pbm": b"P4\n8 1\n\xff",
        "pgm_raw.pgm": b"P5\n1 1\n255\n\x00",
        "ppm_raw.ppm": b"P6\n1 1\n255\n\x00\x00\x00",
        "pam.pam": b"P7\nWIDTH 1\nHEIGHT 1\nDEPTH 1\nMAXVAL 255\n"
                   b"TUPLTYPE GRAYSCALE\nENDHDR\n\x00",
        # text / xml / playlists / subtitles
        "sdp.sdp": b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\n"
                   b"t=0 0\r\nm=audio 0 RTP/AVP 0\r\n",
        "hls.m3u8": b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n"
                    b"#EXTINF:9.0,\nseg0.ts\n",
        "ssa.ssa": b"[Script Info]\nScriptType: v4.00\n\n[Events]\n",
        "mcc.mcc": b"File Format=MacCaption_MCC V1.0\n",
        "cmml.cmml": b"CMML\x00\x00\x00\x00" + pad,
        "uri_list.txt": b"# urilist\r\nhttp://example.com/a\r\n",
        "utf16le.txt": b"\xff\xfeh\x00e\x00l\x00l\x00o\x00",
        "utf16be.txt": b"\xfe\xff\x00h\x00e\x00l\x00l\x00o",
        "utf32le.txt": b"\xff\xfe\x00\x00h\x00\x00\x00",
        "postscript.ps": b"%!PS-Adobe-3.0\n%%EOF\n",
        "dash.mpd": b"<?xml version=\"1.0\"?><MPD xmlns=\"urn:mpeg:dash:"
                    b"schema:mpd:2011\"></MPD>",
        "ttml.ttml": b"<?xml version=\"1.0\"?><tt xmlns=\"http://www.w3.org/"
                     b"ns/ttml\"></tt>",
        "smil.smil": b"<?xml version=\"1.0\"?><smil><body></body></smil>",
        # ar / tar already-ish; ar archive
        "ar.a": b"!<arch>\n" + b"foo/            0  0   0   100644 4    `\n"
                b"\x00\x00\x00\x00",
        # tracker module formats (4cc / signature)
        "mod_xm.xm": b"Extended Module: seed" + b"\x00" * 37 + b"\x1a",
        "mod_it.it": b"IMPM" + pad,
        "mod_dbm.dbm": b"DBM0" + pad,
        "mod_dsm.dsm": b"DSMF" + pad,
        "mod_far.far": b"FAR\xfe" + pad,
        "mod_mmd.med": b"MMD0" + pad,
        "mod_okta.okt": b"OKTASONG" + pad,
        "mod_psm.psm": b"PSM " + pad,
        "digibooster.dbm": b"DIGI Booster module\x00" + pad,
        # codec elementary streams (syncword / NAL)
        "ac3.ac3": (b"\x0b\x77\x00\x00\x3c\x00" + b"\x00" * 250) * 3,
        "dts.dts": (b"\x7f\xfe\x80\x01\x00\x00\x00\x00" + b"\x00" * 120) * 3,
        "eac3.eac3": (b"\x0b\x77\x18\x00" + b"\x00" * 200) * 3,
        "h263.h263": b"\x00\x00\x80\x02" + pad,
        "h265.h265": b"\x00\x00\x00\x01\x40\x01" + b"\x00" * 8 +
                     b"\x00\x00\x00\x01\x42\x01" + b"\x00" * 8 +
                     b"\x00\x00\x00\x01\x44\x01" + pad,
        "h266.h266": b"\x00\x00\x00\x01\x00\x79" + b"\x00" * 8 +
                     b"\x00\x00\x00\x01\x00\x81" + pad,
        "mpeg_es.mpv": b"\x00\x00\x01\xb3\x16\x01\x20\xc4" + b"\x00" * 16 +
                       b"\x00\x00\x01\xb8" + pad,
        "mpeg4_es.m4v": b"\x00\x00\x01\xb0\x01\x00\x00\x01\xb5" + pad,
        "av1.obu": b"\x12\x00\x0a\x0b\x00\x00\x00\x24\xcf\xbf\x1b\xe0\x01\x40"
                   + pad,
        "dv.dv": b"\x1f\x07\x00\x3f" + b"\x00" * 76 + b"\x1f\x07\x01\x3f" + pad,
        "pva.pva": b"AV\x01\x00" + pad,
    }
    for name, data in table.items():
        w(d, name, data)

    # ---- Ogg-wrapped codec identification packets ----
    def ogg_packet(payload, serial=1):
        nseg = (len(payload) + 254) // 255
        segtab = bytes([255] * (nseg - 1) +
                       [len(payload) - 255 * (nseg - 1)]) if nseg else b"\x00"
        return (b"OggS" + bytes([0, 0x02]) + b"\x00" * 8 +
                struct.pack("<I", serial) + struct.pack("<I", 0) +
                struct.pack("<I", 0) + bytes([nseg]) + segtab + payload)
    w(d, "ogg_theora.ogg", ogg_packet(b"\x80theora\x03\x02\x00" + pad))
    w(d, "ogg_speex.spx", ogg_packet(b"Speex   1.2.0" + b"\x00" * 67))
    w(d, "ogg_celt.ogg", ogg_packet(b"CELT    " + pad))
    w(d, "ogg_kate.ogg", ogg_packet(b"\x80kate\x00\x00\x00" + pad))
    w(d, "ogg_flac.ogg", ogg_packet(b"\x7fFLAC\x01\x00" + b"fLaC" + pad))
    w(d, "ogg_skeleton.ogg", ogg_packet(b"fishead\x00" + pad))

    # ---- tar (ustar magic at offset 257) ----
    tar = bytearray(b"seedfile.txt".ljust(100, b"\x00"))
    tar += b"0000644\x00" + b"0000000\x00" + b"0000000\x00"      # mode/uid/gid
    tar += b"00000000000\x00" + b"00000000000\x00"               # size/mtime
    tar += b"        "                                            # chksum
    tar += b"0"                                                   # typeflag
    tar = tar.ljust(257, b"\x00") + b"ustar\x0000"               # magic+version
    tar = tar.ljust(512, b"\x00")
    w(d, "tar.tar", bytes(tar))

    # ---- tracker mod with M.K. signature at offset 1080 ----
    modk = bytearray(b"\x00" * 1080)
    modk[0:20] = b"seed song name".ljust(20, b"\x00")
    modk += b"M.K." + b"\x00" * 64
    w(d, "mod_mk.mod", bytes(modk))


# ==========================================================================
# gst-discoverer  (uses ogg/theora/vorbis demuxers)
# ==========================================================================
# --------------------------------------------------------------------------
# Complete containers for gst-discoverer.
#
# gst-discoverer runs the real push pipeline (typefind -> demux -> parse ->
# caps), so unlike the typefind target it needs structurally complete files:
# the demuxer must parse a track and emit caps for the discovery/description/
# codec-utils code to run. These builders emit small but complete containers
# for the demuxers the build enables (ogg, isomp4/qtdemux, matroska, avi).
# --------------------------------------------------------------------------

def _ogg_crc(data):
    crc = 0
    for byte in data:
        crc ^= byte << 24
        crc &= 0xffffffff
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04c11db7) & 0xffffffff \
                if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return crc


def _ogg_page(serial, seq, packets, bos=False, eos=False, granule=0):
    """Assemble one Ogg page carrying whole packets (with lacing + CRC)."""
    segtab = bytearray()
    body = bytearray()
    for p in packets:
        n = len(p)
        while n >= 255:
            segtab.append(255)
            n -= 255
        segtab.append(n)
        body += p
    htype = (0x02 if bos else 0) | (0x04 if eos else 0)
    hdr = b"OggS" + bytes([0, htype]) + struct.pack("<q", granule) + \
        struct.pack("<I", serial) + struct.pack("<I", seq) + \
        struct.pack("<I", 0) + bytes([len(segtab)]) + bytes(segtab)
    page = bytearray(hdr + body)
    page[22:26] = struct.pack("<I", _ogg_crc(page))
    return bytes(page)


def _ogg_stream(serial, headers, audio_granule=1024):
    """id header (BOS) + remaining headers + one EOS audio page."""
    pages = [_ogg_page(serial, 0, [headers[0]], bos=True)]
    if len(headers) > 1:
        pages.append(_ogg_page(serial, 1, headers[1:]))
    pages.append(_ogg_page(serial, len(pages), [b"\x00" * 8], eos=True,
                           granule=audio_granule))
    return b"".join(pages)


def _ogg_vorbis():
    idh = b"\x01vorbis" + struct.pack("<I", 0) + bytes([2]) + \
        struct.pack("<I", 44100) + struct.pack("<iii", 0, 128000, 0) + \
        bytes([0xB8]) + bytes([0x01])
    vendor = b"gst-fuzz"
    comments = [b"TITLE=Fuzz", b"ARTIST=Seed", b"ALBUM=Corpus"]
    ch = b"\x03vorbis" + struct.pack("<I", len(vendor)) + vendor + \
        struct.pack("<I", len(comments))
    for c in comments:
        ch += struct.pack("<I", len(c)) + c
    ch += bytes([0x01])
    setup = b"\x05vorbis" + b"\x00" * 32 + bytes([0x01])
    return _ogg_stream(0xC0FFEE, [idh, ch, setup])


def _ogg_opus():
    idh = b"OpusHead" + bytes([1, 2]) + struct.pack("<H", 312) + \
        struct.pack("<I", 48000) + struct.pack("<h", 0) + bytes([0])
    tags = b"OpusTags" + struct.pack("<I", 8) + b"gst-fuzz" + \
        struct.pack("<I", 2) + struct.pack("<I", 10) + b"TITLE=Fuzz" + \
        struct.pack("<I", 11) + b"ARTIST=Seed"
    return _ogg_stream(0xABCDE, [idh, tags], audio_granule=960)


def _ogg_theora():
    idh = bytes([0x80]) + b"theora" + bytes([3, 2, 1]) + \
        struct.pack(">H", 20) + struct.pack(">H", 15) + b"\x00" * 24
    com = bytes([0x81]) + b"theora" + struct.pack("<I", 8) + b"gst-fuzz" + \
        struct.pack("<I", 1) + struct.pack("<I", 10) + b"TITLE=Fuzz"
    setup = bytes([0x82]) + b"theora" + b"\x00" * 16
    return _ogg_stream(0x77777, [idh, com, setup])


def _ogg_flac():
    streaminfo = b"\x00\x00\x00\x22" + b"\x10\x00\x10\x00" + \
        b"\x00\x00\x00\x00\x00\x00" + b"\x0a\xc4\x42\xf0" + b"\x00" * 16
    idh = b"\x7fFLAC\x01\x00" + struct.pack(">H", 1) + b"fLaC" + \
        b"\x00" + streaminfo
    vc = b"gst-fuzz"
    comments = [b"TITLE=Fuzz"]
    body = struct.pack("<I", len(vc)) + vc + struct.pack("<I", len(comments))
    for c in comments:
        body += struct.pack("<I", len(c)) + c
    meta = bytes([0x84]) + struct.pack(">I", len(body))[1:] + body
    return _ogg_stream(0x5151, [idh, meta])


def _ogg_speex():
    hdr = b"Speex   " + b"1.2.0".ljust(20, b"\x00") + struct.pack("<I", 1) + \
        struct.pack("<I", 80) + struct.pack("<I", 44100) + \
        struct.pack("<I", 1) + struct.pack("<I", 0) + struct.pack("<I", 1) + \
        struct.pack("<I", 0) + struct.pack("<I", 160) + struct.pack("<I", 0) + \
        struct.pack("<I", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + \
        struct.pack("<I", 0)
    com = struct.pack("<I", 8) + b"gst-fuzz" + struct.pack("<I", 0)
    return _ogg_stream(0x99, [hdr, com])


def _avcC():
    sps = bytes([0x67, 0x42, 0x00, 0x1f, 0xac, 0xb2, 0x00, 0x07, 0x00])
    pps = bytes([0x68, 0xce, 0x3c, 0x80])
    return bytes([1, 0x42, 0x00, 0x1f, 0xFF, 0xE1]) + \
        struct.pack(">H", len(sps)) + sps + bytes([1]) + \
        struct.pack(">H", len(pps)) + pps


def _mp4(video=True, audio=True):
    """isobmff with real avc1/avcC and/or mp4a/esds tracks and a 1-sample
    sample table so qtdemux finalises and discovery describes the streams."""
    def box(typ, payload=b""):
        return struct.pack(">I", 8 + len(payload)) + typ + payload

    def fbox(typ, ver, flags, payload=b""):
        return box(typ, bytes([ver]) + struct.pack(">I", flags)[1:] + payload)

    def avc1():
        b = b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16 + \
            struct.pack(">HH", 320, 240) + \
            struct.pack(">II", 0x00480000, 0x00480000) + b"\x00" * 4 + \
            struct.pack(">H", 1) + b"\x00" * 32 + \
            struct.pack(">H", 0x0018) + struct.pack(">H", 0xffff) + \
            box(b"avcC", _avcC())
        return box(b"avc1", b)

    def mp4a():
        asc = bytes([0x12, 0x10])                       # AAC-LC 44.1k stereo

        def desc(tag, p):
            return bytes([tag, len(p)]) + p
        dsi = desc(0x05, asc)
        dcd = desc(0x04, bytes([0x40, 0x15]) + b"\x00" * 3 +
                   struct.pack(">II", 0, 0) + dsi)
        es = desc(0x03, struct.pack(">H", 0) + bytes([0]) + dcd +
                  desc(0x06, bytes([0x02])))
        esds = fbox(b"esds", 0, 0, es)
        b = b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 8 + \
            struct.pack(">HH", 2, 16) + b"\x00" * 4 + \
            struct.pack(">I", 44100 << 16) + esds
        return box(b"mp4a", b)

    def stbl(entry, off):
        return box(b"stbl",
                   fbox(b"stsd", 0, 0, struct.pack(">I", 1) + entry) +
                   fbox(b"stts", 0, 0, struct.pack(">III", 1, 1, 1000)) +
                   fbox(b"stsc", 0, 0, struct.pack(">I", 1) +
                        struct.pack(">III", 1, 1, 1)) +
                   fbox(b"stsz", 0, 0, struct.pack(">III", 0, 1, 16)) +
                   fbox(b"stco", 0, 0, struct.pack(">II", 1, off)))

    def dinf():
        return box(b"dinf", fbox(b"dref", 0, 0, struct.pack(">I", 1) +
                                 fbox(b"url ", 0, 1)))

    def trak(tid, handler, mhdr, entry, timescale, off, w=0, h=0):
        tkhd = fbox(b"tkhd", 0, 7,
                    struct.pack(">IIII", 0, 0, tid, 0) + b"\x00" * 4 +
                    struct.pack(">I", 0) + b"\x00" * 8 +
                    struct.pack(">HHHH", 0, 0, 0, 0) + b"\x00\x01\x00\x00" +
                    b"\x00" * 4 + b"\x00" * 36 +
                    struct.pack(">II", w << 16, h << 16))
        mdhd = fbox(b"mdhd", 0, 0, struct.pack(">IIII", 0, 0, timescale, 0) +
                    struct.pack(">HH", 0x55c4, 0))
        hdlr = fbox(b"hdlr", 0, 0, b"\x00" * 4 + handler + b"\x00" * 12 +
                    b"h\x00")
        minf = box(b"minf", mhdr + dinf() + stbl(entry, off))
        return box(b"trak", tkhd + box(b"mdia", mdhd + hdlr + minf))

    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0x200) +
               b"isomiso2avc1mp41")
    mvhd = fbox(b"mvhd", 0, 0, struct.pack(">IIII", 0, 0, 1000, 0) +
                b"\x00\x01\x00\x00" + b"\x00" * 10 + b"\x00\x01\x00\x00" +
                b"\x00" * 28 + struct.pack(">I", 3))
    vmhd = fbox(b"vmhd", 0, 1, b"\x00" * 8)
    smhd = fbox(b"smhd", 0, 0, b"\x00" * 4)

    # Two passes: size the moov with a placeholder chunk offset, then patch it
    # to the real mdat payload offset.
    def build(off):
        traks = b""
        if video:
            traks += trak(1, b"vide", vmhd, avc1(), 30000, off, 320, 240)
        if audio:
            traks += trak(2, b"soun", smhd, mp4a(), 44100, off)
        return box(b"moov", mvhd + traks)

    moov0 = build(0)
    off = len(ftyp) + len(moov0) + 8
    return ftyp + build(off) + box(b"mdat", b"\x00" * 16)


def _matroska_multicodec():
    """A Matroska segment declaring many codec tracks (vp8/vp9/av1/h264/aac/
    opus/mp3). Each distinct CodecID makes matroskademux emit a distinct caps,
    driving descriptions.c and codec-utils.c."""
    def vint(n):
        for length in range(1, 9):
            if n < (1 << (7 * length)) - 1:
                return (n | (1 << (7 * length))).to_bytes(length, "big")
        return (n | (1 << 56)).to_bytes(8, "big")

    def el(idhex, data):
        return bytes.fromhex(idhex) + vint(len(data)) + data

    def u(n):
        return b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8,
                                                  "big")

    def track(num, ttype, codecid, priv=None, w=320, h=240, rate=44100, ch=2):
        body = el("D7", u(num)) + el("73C5", u(num)) + el("83", u(ttype)) + \
            el("86", codecid)
        if priv is not None:
            body += el("63A2", priv)
        if ttype == 1:
            body += el("E0", el("B0", u(w)) + el("BA", u(h)))
        else:
            body += el("E1", el("B5", struct.pack(">d", rate)) +
                       el("9F", u(ch)))
        return el("AE", body)

    ebml = el("1A45DFA3",
              el("4286", u(1)) + el("42F7", u(1)) + el("42F2", u(4)) +
              el("42F3", u(8)) + el("4282", b"matroska") +
              el("4287", u(4)) + el("4285", u(2)))
    info = el("1549A966", el("2AD7B1", u(1000000)) + el("4D80", b"gst-fuzz") +
             el("5741", b"gst-fuzz") + el("4489", struct.pack(">d", 1000.0)))
    opushead = b"OpusHead" + bytes([1, 2]) + struct.pack("<H", 312) + \
        struct.pack("<I", 48000) + struct.pack("<h", 0) + bytes([0])
    av1c = bytes([0x81, 0x00, 0x00, 0x00]) + \
        bytes([0x0A, 0x0B, 0x00, 0x00, 0x00, 0x24, 0xCF, 0xBF, 0x1B, 0xE0,
               0x01, 0x40])
    tracks = el("1654AE6B",
                track(1, 1, b"V_VP8") + track(2, 1, b"V_VP9") +
                track(3, 1, b"V_AV1", av1c) +
                track(4, 1, b"V_MPEG4/ISO/AVC", _avcC()) +
                track(5, 2, b"A_AAC", bytes([0x12, 0x10])) +
                track(6, 2, b"A_OPUS", opushead) +
                track(7, 2, b"A_MPEG/L3"))

    def simpleblock(tn):
        return el("A3", vint(tn) + struct.pack(">h", 0) + bytes([0x80]) +
                  b"\x00" * 4)
    cluster = el("1F43B675", el("E7", u(0)) + simpleblock(1) + simpleblock(5))
    return ebml + el("18538067", info + tracks + cluster)


def _avi_mjpeg():
    def ck(fourcc, data):
        return fourcc + struct.pack("<I", len(data)) + data + \
            (b"\x00" if len(data) & 1 else b"")

    def lst(name, data):
        return b"LIST" + struct.pack("<I", 4 + len(data)) + name + data
    mjpg = ord('M') | (ord('J') << 8) | (ord('P') << 16) | (ord('G') << 24)
    strh = struct.pack("<4s4sIHHIIIIIIIIhhhh", b"vids", b"MJPG",
                       0, 0, 0, 0, 1, 25, 0, 10, 0, 0xFFFFFFFF, 0, 0, 0, 20, 15)
    bih = struct.pack("<IiiHHIIiiII", 40, 20, 15, 1, 24, mjpg, 0, 0, 0, 0, 0)
    strl = lst(b"strl", ck(b"strh", strh) + ck(b"strf", bih))
    avih = struct.pack("<IIIIIIIIIIIIII", 40000, 25, 0, 0, 1, 0, 1, 0,
                       20, 15, 0, 0, 0, 0)
    hdrl = lst(b"hdrl", ck(b"avih", avih) + strl)
    movi = lst(b"movi", ck(b"00dc", b"\xff\xd8\xff\xd9"))
    body = b"AVI " + hdrl + movi
    return b"RIFF" + struct.pack("<I", len(body)) + body


def gen_discoverer(base):
    d = os.path.join(base, "gst-discoverer")
    os.makedirs(d, exist_ok=True)

    # (1) Format variety: reuse the full typefind seed set. Feeding it to the
    # discovery pipeline drives descriptions.c, missing-plugins.c and
    # gsttypefindhelper.c for ~120 distinct container/codec caps (each caps is
    # typefound, then described / reported as a missing plugin).
    #
    # A few formats are typefind-only: their element aborts (rather than errors
    # out) on the short/partial buffers a discovery push pipeline hands it, so
    # they would crash the discoverer target while it loads the seed corpus.
    # Keep them in the typefind corpus (detection is safe) but not here:
    #   * yuv4mpeg  -- gsty4mdec asserts mapinfo.size >= MAX_STREAM_HEADER_LENGTH
    #                  (128) on a drained sub-128-byte buffer.
    discoverer_skip = {"yuv4mpeg.y4m"}
    tf = os.path.join(base, "typefind")
    if os.path.isdir(tf):
        for name in os.listdir(tf):
            if name in discoverer_skip:
                continue
            shutil.copyfile(os.path.join(tf, name),
                            os.path.join(d, "tf_" + name))

    # (2) Complete containers for the enabled demuxers. These parse into real
    # tracks, so discovery describes the streams and codec-utils.c parses the
    # carried codec_data (avcC / esds-ASC / av1C / OpusHead). The Ogg files
    # also carry Vorbis/Opus/FLAC comment headers, driving gstvorbistag.c.
    w(d, "ogg_start.ogg", _ogg())
    w(d, "ogg_vorbis.ogg", _ogg_vorbis())
    w(d, "ogg_opus.ogg", _ogg_opus())
    w(d, "ogg_theora.ogv", _ogg_theora())
    w(d, "ogg_flac.oga", _ogg_flac())
    w(d, "ogg_speex.spx", _ogg_speex())
    w(d, "mp4_h264_aac.mp4", _mp4(video=True, audio=True))
    w(d, "mp4_h264.mp4", _mp4(video=True, audio=False))
    w(d, "mp4_aac.m4a", _mp4(video=False, audio=True))
    w(d, "matroska_multicodec.mkv", _matroska_multicodec())
    w(d, "avi_mjpeg.avi", _avi_mjpeg())
    w(d, "wav_pcm.wav", _riff_wav())


# ==========================================================================
def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "gst_seeds"
    os.makedirs(out, exist_ok=True)
    gen_codec_utils(out)
    gen_tag(out)
    gen_subparse(out)
    gen_typefind(out)
    gen_discoverer(out)
    total = 0
    for root, _, files in os.walk(out):
        total += len(files)
    sys.stderr.write("generate_seeds.py: wrote %d seeds under %s\n"
                     % (total, out))


if __name__ == "__main__":
    main()

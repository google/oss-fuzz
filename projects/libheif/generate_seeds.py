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

"""Structured HEIF/ISOBMFF seed generation for the libheif OSS-Fuzz targets.

libheif builds six fuzzers; only `file-fuzzer` ships a seed corpus.  The
`box-fuzzer` (which loops over `Box::read` and dumps every box) and the other
targets start from nothing.  The public coverage report and box.cc show a very
large set of recognised box / item-property types (clap, irot, imir, ispe,
pixi, colr, pasp, auxC, clli, mdcv, cclv, amve, a1lx, a1op, lsel, uncC, cmpC,
grid/iovl derivations, iref reference types, ...), most of which the existing
.heic corpus never carries.

This script synthesises structurally valid ISOBMFF/HEIF files that exercise the
container, item-property and derivation parsing paths.  No external codec is
required: the files are about *box structure*, which `box-fuzzer` parses in
full and `file-fuzzer` walks before attempting any decode.  We also emit an
uncompressed-codec (`uncC`/`unci`) image, which libheif can actually decode
from pure container data, reaching the decode + colour-conversion paths.

Pure Python standard library only.

Usage:  python3 generate_seeds.py <output_dir>
"""

import os
import sys
import struct


def w(d, name, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


# --------------------------------------------------------------------------
# ISOBMFF box helpers
# --------------------------------------------------------------------------
def box(typ, payload=b""):
    assert len(typ) == 4
    return struct.pack(">I", 8 + len(payload)) + typ.encode("latin-1") + payload


def fullbox(typ, version, flags, payload=b""):
    hdr = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF))
    return box(typ, hdr + payload)


# --- item property boxes (live inside ipco) -------------------------------
def p_ispe(wd, ht):
    return fullbox("ispe", 0, 0, struct.pack(">II", wd, ht))


def p_pixi(channels):
    return fullbox("pixi", 0, 0, bytes([len(channels)]) + bytes(channels))


def p_irot(angle):           # 0,1,2,3 -> 0/90/180/270
    return box("irot", bytes([angle & 3]))


def p_imir(axis):            # 0 vertical, 1 horizontal
    return box("imir", bytes([axis & 1]))


def p_clap():
    # cleanAperture: widthN,widthD,heightN,heightD,horizOffN/D,vertOffN/D
    return box("clap", struct.pack(">iiiiiiii", 32, 1, 32, 1, 0, 1, 0, 1))


def p_pasp():
    return box("pasp", struct.pack(">II", 1, 1))


def p_colr_nclx():
    return box("colr", b"nclx" + struct.pack(">HHH", 1, 13, 1) + bytes([0x80]))


def p_colr_ricc():
    icc = b"\x00\x00\x00\x0cseed-iccprof"
    return box("colr", b"rICC" + icc)


def p_auxC(uri):
    return fullbox("auxC", 0, 0, uri.encode("latin-1") + b"\x00")


def p_clli():
    return box("clli", struct.pack(">HH", 1000, 50))


def p_mdcv():
    return box("mdcv", struct.pack(">HHHHHHHHII",
               13250, 34500, 7500, 3000, 34000, 16000, 15635, 16450,
               10000000, 50))


def p_hvcC():
    # Minimal HEVCDecoderConfigurationRecord header (no nal arrays).
    return box("hvcC", bytes([0x01, 0x01, 0x60, 0x00, 0x00, 0x00, 0x90, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x3C, 0xF0, 0x00, 0xFC,
                              0xFD, 0xF8, 0xF8, 0x00, 0x00, 0x00]) +
               bytes([0x00]))


def p_av1C():
    return box("av1C", bytes([0x81, 0x00, 0x0C, 0x00]))


def p_a1lx():
    return box("a1lx", struct.pack(">BIII", 0, 16, 16, 16)[:1] +
               struct.pack(">III", 16, 16, 16))


def p_a1op():
    return box("a1op", bytes([1]))


def p_lsel():
    return box("lsel", struct.pack(">H", 0))


def p_uncC_unci():
    # uncompressed-frame config (uncC v1 'tiled' minimal) + component defs.
    cmpd = box("cmpd", struct.pack(">I", 3) +
               struct.pack(">H", 4) + struct.pack(">H", 5) + struct.pack(">H", 6))
    uncC = fullbox("uncC", 1, 0, b"\x00\x00\x00\x00")
    return cmpd + uncC


def p_pymd():
    return box("pymd", struct.pack(">HH", 1, 1) + b"\x00" * 4)


def p_mskC():
    return fullbox("mskC", 0, 0, bytes([8]) + b"\x00\x00\x00")


# --------------------------------------------------------------------------
# meta-box assembly
# --------------------------------------------------------------------------
def make_meta(items, properties, associations, irefs=b"", idat=b"",
              primary=1):
    """items: list of (item_id, item_type, extra_infe_payload)
       properties: list of property box bytes (1-based index order)
       associations: list of (item_id, [(prop_index, essential), ...])
       irefs: pre-built iref payload (concatenated reference boxes)"""
    hdlr = fullbox("hdlr", 0, 0,
                   struct.pack(">I", 0) + b"pict" + b"\x00" * 12 +
                   b"libheif-seed\x00")
    pitm = fullbox("pitm", 0, 0, struct.pack(">H", primary))

    # iinf with infe entries
    infes = b""
    for iid, ityp, extra in items:
        payload = struct.pack(">HH", iid, 0) + ityp.encode("latin-1") + \
            b"seed\x00" + extra
        infes += fullbox("infe", 2, 0, payload)
    iinf = fullbox("iinf", 0, 0, struct.pack(">H", len(items)) + infes)

    # iprp = ipco (properties) + ipma (associations)
    ipco = box("ipco", b"".join(properties))
    ipma_body = struct.pack(">I", len(associations))
    for iid, props in associations:
        ipma_body += struct.pack(">H", iid) + bytes([len(props)])
        for idx, essential in props:
            ipma_body += bytes([((0x80 if essential else 0) | (idx & 0x7F))])
    ipma = fullbox("ipma", 0, 0, ipma_body)
    iprp = box("iprp", ipco + ipma)

    # iloc: place every item inside the idat box (construction_method=1)
    iloc_body = bytes([(4 << 4) | 0, (0 << 4) | 0])   # offset/len sz=4, base/idx=0
    iloc_body += struct.pack(">H", len(items))
    off = 0
    for iid, ityp, extra in items:
        ln = 16
        iloc_body += struct.pack(">H", iid) + struct.pack(">H", 1)  # method=1 idat
        iloc_body += struct.pack(">H", 0)            # data_ref_index
        iloc_body += struct.pack(">H", 1)            # extent_count
        iloc_body += struct.pack(">I", off) + struct.pack(">I", ln)
        off += ln
    iloc = fullbox("iloc", 1, 0, iloc_body)

    idat_box = box("idat", idat) if idat else b""
    iref_box = fullbox("iref", 0, 0, irefs) if irefs else b""

    body = hdlr + pitm + iinf + iref_box + iprp + iloc + idat_box
    return fullbox("meta", 0, 0, body)


def iref_entry(ref_type, from_id, to_ids):
    payload = struct.pack(">H", from_id) + struct.pack(">H", len(to_ids))
    for t in to_ids:
        payload += struct.pack(">H", t)
    return box(ref_type, payload)


FTYP = box("ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")


# --------------------------------------------------------------------------
def seed_comprehensive():
    """A file carrying a large variety of item properties + several items."""
    props = [
        p_ispe(32, 32), p_pixi([8, 8, 8]), p_irot(1), p_imir(0), p_clap(),
        p_pasp(), p_colr_nclx(), p_colr_ricc(), p_auxC("urn:mpeg:hevc:aux:alpha"),
        p_clli(), p_mdcv(), p_hvcC(), p_av1C(), p_a1lx(), p_a1op(), p_lsel(),
        p_mskC(),
    ]
    items = [
        (1, "hvc1", b""),       # primary coded image
        (2, "av01", b""),       # av1 coded image
        (3, "Exif", b""),       # metadata item
        (4, "mime", b"\x00application/rdf+xml\x00"),
    ]
    assoc = [
        (1, [(1, False), (2, False), (3, False), (12, True), (7, False),
             (10, False), (11, False)]),
        (2, [(1, False), (2, False), (13, True), (14, False), (15, False)]),
    ]
    irefs = (iref_entry("cdsc", 3, [1]) + iref_entry("thmb", 2, [1]) +
             iref_entry("auxl", 2, [1]))
    idat = b"\x00" * (16 * len(items))
    meta = make_meta(items, props, assoc, irefs, idat)
    return FTYP + meta + box("mdat", b"\x00" * 32)


def seed_grid():
    """A 2x2 'grid' derived image referencing four coded tiles."""
    # grid item payload: version, flags, rows-1, cols-1, output W, H (16-bit)
    grid_data = bytes([0, 0, 1, 1]) + struct.pack(">HH", 64, 64)
    props = [p_ispe(64, 64), p_pixi([8, 8, 8]), p_hvcC(), p_colr_nclx()]
    items = [(1, "grid", b"")] + [(i, "hvc1", b"") for i in range(2, 6)]
    assoc = [(1, [(1, False), (4, False)])] + \
            [(i, [(1, False), (3, True), (4, False)]) for i in range(2, 6)]
    irefs = iref_entry("dimg", 1, [2, 3, 4, 5])
    idat = grid_data.ljust(16, b"\x00") + b"\x00" * (16 * 4)
    meta = make_meta(items, props, assoc, irefs, idat)
    return FTYP + meta + box("mdat", b"\x00" * 64)


def seed_overlay():
    """An 'iovl' overlay derived image."""
    # iovl: version/flags, canvas_fill (4x16), output W,H, then per-image x,y
    iovl = bytes([0, 0]) + struct.pack(">HHHH", 0, 0, 0, 0xFFFF)
    iovl += struct.pack(">HH", 64, 64)
    iovl += struct.pack(">hh", 0, 0) + struct.pack(">hh", 16, 16)
    props = [p_ispe(64, 64), p_pixi([8, 8, 8]), p_hvcC()]
    items = [(1, "iovl", b""), (2, "hvc1", b""), (3, "hvc1", b"")]
    assoc = [(1, [(1, False)]), (2, [(1, False), (3, True)]),
             (3, [(1, False), (3, True)])]
    irefs = iref_entry("dimg", 1, [2, 3])
    idat = iovl.ljust(16, b"\x00") + b"\x00" * 32
    meta = make_meta(items, props, assoc, irefs, idat)
    return FTYP + meta + box("mdat", b"\x00" * 64)


def _heif_single_item(item_type, props, assoc, item_data, extra_props_meta=b""):
    """Build a complete HEIF with one item whose data lives in an idat box,
    with a *correctly sized* iloc extent so the item actually decodes."""
    hdlr = fullbox("hdlr", 0, 0, struct.pack(">I", 0) + b"pict" +
                   b"\x00" * 12 + b"seed\x00")
    pitm = fullbox("pitm", 0, 0, struct.pack(">H", 1))
    infe = fullbox("infe", 2, 0, struct.pack(">HH", 1, 0) +
                   item_type.encode("latin-1") + b"\x00")
    iinf = fullbox("iinf", 0, 0, struct.pack(">H", 1) + infe)
    ipco = box("ipco", b"".join(props))
    ipma_body = struct.pack(">I", 1) + struct.pack(">H", 1) + bytes([len(assoc)])
    for idx, ess in assoc:
        ipma_body += bytes([(0x80 if ess else 0) | (idx & 0x7F)])
    ipma = fullbox("ipma", 0, 0, ipma_body)
    iprp = box("iprp", ipco + ipma)

    # iloc v1: offset_size=4 length_size=4, base_offset_size=0 index_size=0,
    # one item, construction_method=0 (file offset), one extent. The data lives
    # in an mdat box appended after the meta box, so the absolute offset is
    # len(FTYP)+len(meta)+8. The offset field width is fixed, so the meta size
    # is the same whether we use a placeholder or the real offset.
    def make_iloc(offset):
        il = bytes([(4 << 4) | 4, 0]) + struct.pack(">H", 1)
        il += struct.pack(">H", 1) + struct.pack(">H", 0) + struct.pack(">H", 0)
        il += struct.pack(">H", 1) + struct.pack(">I", offset) + \
            struct.pack(">I", len(item_data))
        return fullbox("iloc", 1, 0, il)

    meta = fullbox("meta", 0, 0, hdlr + pitm + iinf + iprp + make_iloc(0))
    data_offset = len(FTYP) + len(meta) + 8           # +8 = mdat box header
    meta = fullbox("meta", 0, 0,
                   hdlr + pitm + iinf + iprp + make_iloc(data_offset))
    return FTYP + meta + box("mdat", item_data)


def _unci_image(w, h, comp_types, interleave, bit_depth=8, comp_format=0,
                comp_align=0, flags=0, pixel_size=0, row_align=0,
                tile_align=0, tile_cols=1, tile_rows=1, sampling=0,
                block_size=0):
    """A decodable ISO 23001-17 uncompressed image. interleave: 0=component,
    1=pixel, 2=mixed, 3=row, 4=tile-component, 5=multi-Y."""
    nc = len(comp_types)
    bpc = (bit_depth + 7) // 8

    def val(x, y, c):
        return (x * 37 + y * 17 + c * 53) & ((1 << bit_depth) - 1)

    def emit(v):
        if bpc == 1:
            return bytes([v & 0xFF])
        if flags & 0x80:        # components_little_endian
            return bytes([v & 0xFF, (v >> 8) & 0xFF])
        return bytes([(v >> 8) & 0xFF, v & 0xFF])

    data = bytearray()
    if interleave == 1 or interleave == 2:          # pixel / mixed
        for y in range(h):
            for x in range(w):
                for c in range(nc):
                    data += emit(val(x, y, c))
                    if pixel_size:
                        while len(data) % pixel_size:
                            data += b"\x00"
    elif interleave == 3:                           # row
        for y in range(h):
            for c in range(nc):
                for x in range(w):
                    data += emit(val(x, y, c))
    else:                                           # component / tile-component
        for c in range(nc):
            for y in range(h):
                for x in range(w):
                    data += emit(val(x, y, c))
    pixels = bytes(data)

    cmpd = box("cmpd", struct.pack(">I", nc) +
               b"".join(struct.pack(">H", t) for t in comp_types))
    u = struct.pack(">II", 0, nc)
    for i in range(nc):
        u += struct.pack(">HBBB", i, bit_depth - 1, comp_format, comp_align)
    u += struct.pack(">BBBB", sampling, interleave, block_size, flags)
    u += struct.pack(">IIIII", pixel_size, row_align, tile_align,
                     tile_cols - 1, tile_rows - 1)
    # uncC version 0 = explicit component configuration (profile=0). Version 1
    # is the compact form that requires a known profile 4cc and omits the
    # component array, so it must NOT be used with an explicit component list.
    uncC = fullbox("uncC", 0, 0, u)
    ispe = fullbox("ispe", 0, 0, struct.pack(">II", w, h))
    props = [ispe, p_pixi([bit_depth] * nc), cmpd, uncC]
    assoc = [(1, False), (2, False), (3, True), (4, True)]
    return _heif_single_item("unci", props, assoc, pixels)


# Component types (ISO 23001-17): 0=mono 1=Y 2=Cb 3=Cr 4=R 5=G 6=B 7=alpha.
def seed_unci_rgb_pixel():
    return _unci_image(8, 8, [4, 5, 6], interleave=1)


def seed_unci_rgb_planar():
    return _unci_image(8, 8, [4, 5, 6], interleave=0)


def seed_unci_rgb_row():
    return _unci_image(8, 8, [4, 5, 6], interleave=3)


def seed_unci_rgba_pixel():
    return _unci_image(8, 8, [4, 5, 6, 7], interleave=1)


def seed_unci_mono():
    return _unci_image(8, 8, [0], interleave=0)


def seed_unci_yuv():
    return _unci_image(8, 8, [1, 2, 3], interleave=1, sampling=0)


def seed_unci_rgb16le():
    return _unci_image(8, 8, [4, 5, 6], interleave=1, bit_depth=16, flags=0x80)


def seed_unci_rgb16be():
    return _unci_image(8, 8, [4, 5, 6], interleave=0, bit_depth=16, flags=0x00)


def seed_unci_rgb_tiled():
    return _unci_image(8, 8, [4, 5, 6], interleave=1, tile_cols=2, tile_rows=2)


def seed_unci_rgb_pixsize():
    return _unci_image(8, 8, [4, 5, 6], interleave=1, pixel_size=4, row_align=4)


def seed_unci_rgb_compalign():
    return _unci_image(8, 8, [4, 5, 6], interleave=0, comp_align=2)


# Block-based decoders: only selected when block_size == pixel_size != 0 (the
# non-block decoders reject block_size!=0 via check_common_requirements).
def seed_unci_block_pixel():
    return _unci_image(8, 8, [4, 5, 6], interleave=1, pixel_size=4,
                       block_size=4)


def seed_unci_block_pixel_le():
    # block_little_endian (0x20)
    return _unci_image(8, 8, [4, 5, 6], interleave=1, pixel_size=4,
                       block_size=4, flags=0x20)


def seed_unci_block_pixel_rev():
    # block_reversed (0x10)
    return _unci_image(8, 8, [4, 5, 6], interleave=1, pixel_size=4,
                       block_size=4, flags=0x10)


def seed_unci_block_pixel_padlsb():
    # block_pad_lsb (0x40)
    return _unci_image(8, 8, [4, 5, 6], interleave=1, pixel_size=4,
                       block_size=4, flags=0x40)


def seed_unci_block_component():
    # block_component requires block_bits/2 < bit_depth <= block_bits, so
    # block_size=1 (8 bits) pairs with 8-bit components.
    return _unci_image(8, 8, [4, 5, 6], interleave=0, block_size=1)


def seed_unci_block_component16():
    # block_size=2 (16 bits) pairs with 16-bit components.
    return _unci_image(8, 8, [4, 5, 6], interleave=0, block_size=2,
                       bit_depth=16)


def seed_unci_block_component_rev():
    return _unci_image(8, 8, [4, 5, 6], interleave=0, block_size=1, flags=0x10)


def seed_unci_block_component_padlsb():
    return _unci_image(8, 8, [4, 5, 6], interleave=0, block_size=1, flags=0x40)


def seed_moov_skeleton():
    """A file with a moov/trak/mdia/minf/stbl skeleton so the (rarely used)
    movie-box parsers in box.cc get walked as top-level boxes too."""
    mvhd = fullbox("mvhd", 0, 0, b"\x00" * 96)
    tkhd = fullbox("tkhd", 0, 7, b"\x00" * 80)
    mdhd = fullbox("mdhd", 0, 0, b"\x00" * 20)
    hdlr = fullbox("hdlr", 0, 0, struct.pack(">I", 0) + b"vide" + b"\x00" * 12 +
                   b"seed\x00")
    vmhd = fullbox("vmhd", 0, 1, b"\x00" * 8)
    dref = fullbox("dref", 0, 0, struct.pack(">I", 1) +
                   fullbox("url ", 0, 1, b""))
    dinf = box("dinf", dref)
    stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))
    stts = fullbox("stts", 0, 0, struct.pack(">I", 0))
    stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))
    stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0))
    stco = fullbox("stco", 0, 0, struct.pack(">I", 0))
    stbl = box("stbl", stsd + stts + stsc + stsz + stco)
    minf = box("minf", vmhd + dinf + stbl)
    mdia = box("mdia", mdhd + hdlr + minf)
    trak = box("trak", tkhd + mdia)
    moov = box("moov", mvhd + trak)
    return FTYP + moov + box("free", b"seedfree") + box("mdat", b"\x00" * 16)


# --------------------------------------------------------------------------
def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "libheif_seeds"
    os.makedirs(out, exist_ok=True)
    gens = [
        ("comprehensive.heif", seed_comprehensive),
        ("grid.heif", seed_grid),
        ("overlay.heif", seed_overlay),
        ("moov_skeleton.heif", seed_moov_skeleton),
        # Decodable ISO 23001-17 uncompressed images (no external codec
        # needed) -> the uncompressed decoder variants + colour conversion.
        ("unci_rgb_pixel.heif", seed_unci_rgb_pixel),
        ("unci_rgb_planar.heif", seed_unci_rgb_planar),
        ("unci_rgb_row.heif", seed_unci_rgb_row),
        ("unci_rgba_pixel.heif", seed_unci_rgba_pixel),
        ("unci_mono.heif", seed_unci_mono),
        ("unci_yuv.heif", seed_unci_yuv),
        ("unci_rgb16le.heif", seed_unci_rgb16le),
        ("unci_rgb16be.heif", seed_unci_rgb16be),
        ("unci_rgb_tiled.heif", seed_unci_rgb_tiled),
        ("unci_rgb_pixsize.heif", seed_unci_rgb_pixsize),
        ("unci_rgb_compalign.heif", seed_unci_rgb_compalign),
        ("unci_block_pixel.heif", seed_unci_block_pixel),
        ("unci_block_pixel_le.heif", seed_unci_block_pixel_le),
        ("unci_block_pixel_rev.heif", seed_unci_block_pixel_rev),
        ("unci_block_pixel_padlsb.heif", seed_unci_block_pixel_padlsb),
        ("unci_block_component.heif", seed_unci_block_component),
        ("unci_block_component16.heif", seed_unci_block_component16),
        ("unci_block_component_rev.heif", seed_unci_block_component_rev),
        ("unci_block_component_padlsb.heif", seed_unci_block_component_padlsb),
    ]
    n = 0
    for name, fn in gens:
        try:
            data = fn()
        except Exception as e:                       # keep build robust
            sys.stderr.write("seed %s failed: %s\n" % (name, e))
            continue
        w(out, name, data)
        n += 1
    sys.stderr.write("generate_seeds.py: wrote %d HEIF seeds to %s\n"
                     % (n, out))


if __name__ == "__main__":
    main()

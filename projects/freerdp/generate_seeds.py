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
"""Structured seed generator for the FreeRDP ``TestFuzzCodecs`` harness.

``TestFuzzCodecs`` feeds one buffer into several codec decoders but ships no
seed corpus, so mutation never forms a valid RemoteFX message -- in production
the RemoteFX tile-decode path is dark (``rfx_rlgr.c`` 0%, ``rfx_decode.c`` 0%,
``sse/rfx_sse2.c`` 3.8%).  That code decodes attacker-controlled screen updates
(RLGR entropy -> dequantise -> inverse DWT -> YCoCg->RGB): memory-unsafe paths.

This script emits structurally valid RemoteFX bitstreams as a decodable scaffold
to mutate from.  It ports FreeRDP's RLGR1/RLGR3 encoder and MSB-first bit writer
(``rfx_rlgr.c`` / ``rfx_bitstream.h``) and mirrors the framing in ``rfx.c``.
The decoder, not this generator, is the attack surface.

RemoteFX is the only seed-limited codec here; the others (planar, xcrush,
ncrush, mppc, interleaved, clear, zgfx, nsc) are already corpus-covered to their
decode-reachable extent, so seeds for them were measured to add nothing and are
not emitted.  Seeds are deterministic and additive, so they cannot digress.

Usage: generate_seeds.py <output-dir>
"""
import os
import struct
import sys

# ---------------------------------------------------------------------------
# RLGR encoder (port of libfreerdp/codec/rfx_rlgr.c encode path)
# ---------------------------------------------------------------------------
KPMAX = 80  # max value for kp or krp
LSGR = 3    # shift count to convert kp to k
UP_GR = 4   # increase in kp after a zero run in RL mode
DN_GR = 6   # decrease in kp after a nonzero symbol in RL mode
UQ_GR = 3   # increase in kp after nonzero symbol in GR mode
DQ_GR = 3   # decrease in kp after zero symbol in GR mode


class BitWriter:
    """MSB-first bit writer matching rfx_bitstream_put_bits()."""

    def __init__(self):
        self.out = bytearray()
        self._cur = 0
        self._bits_left = 8

    def put_bits(self, bits, nbits):
        bits &= 0xFFFF  # the C code stores the value in a UINT16
        while nbits > 0:
            b = nbits if nbits <= self._bits_left else self._bits_left
            self._cur |= ((bits >> (nbits - b)) & ((1 << b) - 1)) << (self._bits_left - b)
            self._bits_left -= b
            nbits -= b
            if self._bits_left == 0:
                self.out.append(self._cur)
                self._cur = 0
                self._bits_left = 8

    def flush(self):
        if self._bits_left != 8:
            self.put_bits(0, 8 - self._bits_left)

    def bytes(self):
        return bytes(self.out)


def _update_param(param, delta):
    """Clamp param to [0, KPMAX]; return (param, k = param >> LSGR)."""
    if delta < 0:
        ud = -delta
        param = 0 if ud > param else param - ud
    else:
        param += delta
    if param > KPMAX:
        param = KPMAX
    return param, param >> LSGR


def _output_bit(bs, count, bit):
    b = 0xFFFF if bit else 0
    rem = count % 16
    x = 0
    while x < count - rem:
        bs.put_bits(b, 16)
        x += 16
    if rem > 0:
        bs.put_bits(b, rem)


def _get2magsign(v):
    return 2 * v if v >= 0 else -2 * v - 1


def _get_min_bits(v):
    n = 0
    while v:
        v >>= 1
        n += 1
    return n


def rlgr_encode(mode, data):
    """Encode a list of INT16 coefficients. mode is 'RLGR1' or 'RLGR3'."""
    bs = BitWriter()
    k = 1
    kp = 1 << LSGR
    krp = 1 << LSGR

    def code_gr(krp_val, val):
        kr = krp_val >> LSGR
        vk = val >> kr
        _output_bit(bs, vk, 1)
        _output_bit(bs, 1, 0)
        if kr:
            bs.put_bits(val & ((1 << kr) - 1), kr)
        if vk == 0:
            krp_val, _ = _update_param(krp_val, -2)
        elif vk > 1:
            krp_val, _ = _update_param(krp_val, vk)
        return krp_val

    n = len(data)
    idx = 0

    def get_next():
        nonlocal idx
        if idx < n:
            v = data[idx]
            idx += 1
            return v
        return 0

    while idx < n:
        if k:
            # RUN-LENGTH MODE
            num_zeros = 0
            inp = get_next()
            while inp == 0 and idx < n:
                num_zeros += 1
                inp = get_next()
            # get_next consumed the final zero without counting it in the loop
            if inp == 0 and idx >= n:
                num_zeros += 1

            runmax = 1 << k
            while num_zeros >= runmax:
                _output_bit(bs, 1, 0)
                num_zeros -= runmax
                kp, k = _update_param(kp, UP_GR)
                runmax = 1 << k

            _output_bit(bs, 1, 1)         # terminate the run
            bs.put_bits(num_zeros, k)     # remaining run length in k bits

            mag = -inp if inp < 0 else inp
            sign = 1 if inp < 0 else 0
            _output_bit(bs, 1, sign)
            krp = code_gr(krp, mag - 1 if mag else 0)
            kp, k = _update_param(kp, -DN_GR)
        else:
            # GOLOMB-RICE MODE
            if mode == 'RLGR1':
                inp = get_next()
                two_ms = _get2magsign(inp)
                krp = code_gr(krp, two_ms)
                if two_ms:
                    kp, k = _update_param(kp, -DQ_GR)
                else:
                    kp, k = _update_param(kp, UQ_GR)
            else:  # RLGR3
                two_ms1 = _get2magsign(get_next())
                two_ms2 = _get2magsign(get_next())
                sum2ms = two_ms1 + two_ms2
                krp = code_gr(krp, sum2ms)
                n_idx = _get_min_bits(sum2ms)
                bs.put_bits(two_ms1, n_idx)
                if two_ms1 and two_ms2:
                    kp, k = _update_param(kp, -2 * DQ_GR)
                elif not two_ms1 and not two_ms2:
                    kp, k = _update_param(kp, 2 * UQ_GR)

    bs.flush()
    return bs.bytes()


# ---------------------------------------------------------------------------
# RemoteFX message framing (mirrors libfreerdp/codec/rfx.c write path)
# ---------------------------------------------------------------------------
WBT_SYNC = 0xCCC0
WBT_CODEC_VERSIONS = 0xCCC1
WBT_CHANNELS = 0xCCC2
WBT_CONTEXT = 0xCCC3
WBT_FRAME_BEGIN = 0xCCC4
WBT_FRAME_END = 0xCCC5
WBT_REGION = 0xCCC6
WBT_EXTENSION = 0xCCC7
CBT_REGION = 0xCAC1
CBT_TILESET = 0xCAC2
CBT_TILE = 0xCAC3

WF_MAGIC = 0xCACCACCA
WF_VERSION_1_0 = 0x0100
CT_TILE_64x64 = 0x0040
COL_CONV_ICT = 0x1
CLW_XFORM_DWT_53_A = 0x1
CLW_ENTROPY_RLGR1 = 0x01
CLW_ENTROPY_RLGR3 = 0x04
SCALAR_QUANTIZATION = 0x1

# FreeRDP's default scalar quantization set (rfx_default_quantization_values).
DEFAULT_QUANT = [6, 6, 6, 6, 7, 7, 8, 8, 8, 9]

_U16 = lambda v: struct.pack('<H', v & 0xFFFF)
_U32 = lambda v: struct.pack('<I', v & 0xFFFFFFFF)
_U8 = lambda v: struct.pack('<B', v & 0xFF)


def _entropy_bits(mode):
    return CLW_ENTROPY_RLGR1 if mode == 'RLGR1' else CLW_ENTROPY_RLGR3


def _context_properties(mode):
    # rfx_write_message_context(): flags default to 0.
    p = 0
    p |= (COL_CONV_ICT << 3)
    p |= (CLW_XFORM_DWT_53_A << 5)
    p |= (_entropy_bits(mode) << 9)
    p |= (SCALAR_QUANTIZATION << 13)
    return p


def _tileset_properties(mode):
    # rfx_update_context_properties(): note the different layout from TS_RFX_CONTEXT.
    p = 1                                 # lt
    p |= (COL_CONV_ICT << 4)              # cct
    p |= (CLW_XFORM_DWT_53_A << 6)        # xft
    p |= (_entropy_bits(mode) << 10)      # et
    p |= (SCALAR_QUANTIZATION << 14)      # qt
    return p


def _pack_quant(values):
    # numQuant*5 bytes, each byte = q[2i] + (q[2i+1] << 4)
    out = bytearray()
    for i in range(0, len(values), 2):
        out.append((values[i] + (values[i + 1] << 4)) & 0xFF)
    return bytes(out)


def _block(block_type, body):
    # BlockT: blockType(2) + blockLen(4) + body, blockLen covers the whole block.
    return _U16(block_type) + _U32(6 + len(body)) + body


def _message_header(width, height, mode):
    sync = _block(WBT_SYNC, _U32(WF_MAGIC) + _U16(WF_VERSION_1_0))
    context = (_U16(WBT_CONTEXT) + _U32(13) + _U8(1) + _U8(0xFF) + _U8(0) +
               _U16(CT_TILE_64x64) + _U16(_context_properties(mode)))
    versions = (_U16(WBT_CODEC_VERSIONS) + _U32(10) + _U8(1) + _U8(1) +
                _U16(WF_VERSION_1_0))
    channels = (_U16(WBT_CHANNELS) + _U32(12) + _U8(1) + _U8(0) +
                _U16(width) + _U16(height))
    return sync + context + versions + channels


def _frame_begin(frame_idx=0):
    return (_U16(WBT_FRAME_BEGIN) + _U32(14) + _U8(1) + _U8(0) +
            _U32(frame_idx) + _U16(1))  # numRegions = 1


def _frame_end():
    return _U16(WBT_FRAME_END) + _U32(8) + _U8(1) + _U8(0)


def _region(rects):
    block_len = 15 + len(rects) * 8
    body = (_U16(WBT_REGION) + _U32(block_len) + _U8(1) + _U8(0) + _U8(1) +
            _U16(len(rects)))
    for (x, y, w, h) in rects:
        body += _U16(x) + _U16(y) + _U16(w) + _U16(h)
    body += _U16(CBT_REGION) + _U16(1)  # regionType, numTilesets = 1
    return body


def _region_norects():
    # numRects = 0 -> decoder synthesises a (0,0,width,height) rect and returns
    # early (exercises the numRects < 1 branch in rfx_process_message_region).
    block_len = 15
    return (_U16(WBT_REGION) + _U32(block_len) + _U8(1) + _U8(0) + _U8(1) +
            _U16(0) + _U16(CBT_REGION) + _U16(1))


def _tile(x_idx, y_idx, y_data, cb_data, cr_data, q_y=0, q_cb=0, q_cr=0):
    block_len = 19 + len(y_data) + len(cb_data) + len(cr_data)
    return (_U16(CBT_TILE) + _U32(block_len) +
            _U8(q_y) + _U8(q_cb) + _U8(q_cr) +   # quantIdx Y/Cb/Cr
            _U16(x_idx) + _U16(y_idx) +
            _U16(len(y_data)) + _U16(len(cb_data)) + _U16(len(cr_data)) +
            y_data + cb_data + cr_data)


def _tileset(mode, quant_sets, tiles):
    quant_bytes = b''.join(_pack_quant(q) for q in quant_sets)
    tiles_data = b''.join(tiles)
    block_len = 22 + len(quant_bytes) + len(tiles_data)
    body = (_U16(WBT_EXTENSION) + _U32(block_len) + _U8(1) + _U8(0) +
            _U16(CBT_TILESET) + _U16(0) + _U16(_tileset_properties(mode)) +
            _U8(len(quant_sets)) + _U8(0x40) + _U16(len(tiles)) +
            _U32(len(tiles_data)) + quant_bytes + tiles_data)
    return body


def _frame(mode, width, height, tiles, quant_sets, rects=None, frame_idx=0):
    if rects == 'norects':
        region = _region_norects()
    else:
        region = _region(rects if rects else [(0, 0, width, height)])
    return (_frame_begin(frame_idx) + region +
            _tileset(mode, quant_sets, tiles) + _frame_end())


def build_rfx(mode, width, height, tiles, rects=None, quant_sets=None, frames=1):
    """Assemble a complete RemoteFX message: header + one or more frames."""
    if quant_sets is None:
        quant_sets = [DEFAULT_QUANT]
    out = _message_header(width, height, mode)
    for fi in range(frames):
        out += _frame(mode, width, height, tiles, quant_sets, rects, fi)
    return out


# ---------------------------------------------------------------------------
# Coefficient patterns -- each exercises a different RLGR decode branch.  The
# pixel values are irrelevant; the variety of entropy symbols is what matters.
# ---------------------------------------------------------------------------
def _coeffs_sparse():
    # Long zero runs, occasional small values: run-length mode.
    c = [0] * 400
    for i in range(0, 400, 37):
        c[i] = (i % 11) - 5
    return c


def _coeffs_dense():
    # Consecutive non-zeros: drives k down into Golomb-Rice mode.
    return [((i * 7) % 23) - 11 for i in range(256)]


def _coeffs_bigmag():
    # Large magnitudes: GR codes with vk > 1 and wide remainders.
    c = [0] * 200
    for i in range(0, 200, 5):
        c[i] = ((i * 53) % 4096) - 2048
    return c


def _coeffs_deeprun():
    # One non-zero after a very long zero run: the run-length k-doubling loop
    # and the BitStream_Shift32 (32 leading zero bits) decode path.
    c = [0] * 4096
    c[4000] = 7
    return c


def _coeffs_grzeros():
    # In GR mode, alternate zero / non-zero to hit both the code==0 and
    # code!=0 branches (and the RLGR3 val1/val2 split).
    c = [3, -4, 5, -6, 7]           # drive k down into GR mode
    for i in range(120):
        c += [0, (i % 9) - 4]
    return c


def _coeffs_maxmag():
    # Near-INT16 magnitudes: widest GR code and INT16 boundary handling.
    c = [0] * 128
    for i in range(0, 128, 3):
        c[i] = 32767 if (i % 2 == 0) else -32768
    return c


def _component_data(mode, pattern):
    return rlgr_encode(mode, pattern)


def _write(out_dir, name, data):
    path = os.path.join(out_dir, name)
    with open(path, 'wb') as f:
        f.write(data)
    print('  wrote %-30s %7d bytes' % (name, len(data)))


# A second quantization set with different (still valid, 0..15) shift values,
# so tiles can reference quantIdx 1 and exercise the quant-array handling.
ALT_QUANT = [8, 8, 8, 8, 9, 9, 10, 10, 10, 11]


def gen_rfx(out_dir):
    for mode, tag in (('RLGR1', 'rlgr1'), ('RLGR3', 'rlgr3')):
        y = _component_data(mode, _coeffs_sparse())
        cb = _component_data(mode, _coeffs_dense())
        cr = _component_data(mode, _coeffs_bigmag())

        # Single 64x64 tile.
        tile0 = _tile(0, 0, y, cb, cr)
        _write(out_dir, 'rfx_%s_64x64' % tag, build_rfx(mode, 64, 64, [tile0]))

        # Two horizontally-adjacent tiles (128x64) -> tile loop + grid.
        tile1 = _tile(1, 0, cb, cr, y)
        _write(out_dir, 'rfx_%s_128x64_2tile' % tag,
               build_rfx(mode, 128, 64, [tile0, tile1]))

        # Coefficient patterns that reach extra RLGR decode branches:
        # deep zero runs, Golomb-Rice-mode zeros, and near-INT16 magnitudes.
        dy = _component_data(mode, _coeffs_deeprun())
        gz = _component_data(mode, _coeffs_grzeros())
        mm = _component_data(mode, _coeffs_maxmag())
        _write(out_dir, 'rfx_%s_rlgr_branches' % tag,
               build_rfx(mode, 64, 64, [_tile(0, 0, dy, gz, mm)]))

        # 3x2 tile grid with two quant sets, per-component quant indices.
        grid = []
        for ty in range(2):
            for tx in range(3):
                grid.append(_tile(tx, ty, gz, mm, dy, q_y=0, q_cb=1, q_cr=0))
        _write(out_dir, 'rfx_%s_grid6_2quant' % tag,
               build_rfx(mode, 192, 128, grid, quant_sets=[DEFAULT_QUANT, ALT_QUANT]))

    # Multi-rect region (exercises the region-rect parse loop).
    mode = 'RLGR1'
    y = _component_data(mode, _coeffs_dense())
    cb = _component_data(mode, _coeffs_sparse())
    cr = _component_data(mode, _coeffs_bigmag())
    tile0 = _tile(0, 0, y, cb, cr)
    _write(out_dir, 'rfx_rlgr1_multirect',
           build_rfx(mode, 64, 64, [tile0],
                     rects=[(0, 0, 64, 32), (0, 32, 64, 32)]))

    # numRects == 0 -> decoder synthesises the default rectangle.
    _write(out_dir, 'rfx_rlgr1_norects',
           build_rfx(mode, 64, 64, [tile0], rects='norects'))

    # Two frames in a single message (frame loop + inter-frame state).
    _write(out_dir, 'rfx_rlgr1_2frames',
           build_rfx(mode, 64, 64, [tile0], frames=2))

    # Non-default quantization values (varies the dequant shifts).
    _write(out_dir, 'rfx_rlgr1_altquant',
           build_rfx(mode, 64, 64, [tile0], quant_sets=[ALT_QUANT]))


def main():
    if len(sys.argv) < 2:
        sys.stderr.write('usage: %s <output-dir>\n' % sys.argv[0])
        return 1
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    print('Generating RemoteFX seeds:')
    gen_rfx(out_dir)
    return 0


if __name__ == '__main__':
    sys.exit(main())

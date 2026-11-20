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
"""Generates deterministic NSM protocol seed corpora for nsmd fuzzers."""

import glob
import hashlib
import os
import struct
import sys
import zipfile

MODULE_SPECS = {
    'nsm_base_fuzzer': (0, 7),
    'nsm_debug_token_fuzzer': (4, 7),
    'nsm_device_capability_discovery_fuzzer': (0, 11),
    'nsm_device_configuration_fuzzer': (5, 39),
    'nsm_diagnostics_fuzzer': (4, 33),
    'nsm_firmware_utils_fuzzer': (6, 45),
    'nsm_network_ports_fuzzer': (1, 47),
    'nsm_pci_links_fuzzer': (2, 31),
    'nsm_platform_environmental_fuzzer': (3, 122),
    'nsm_powersmoothing_v2_fuzzer': (3, 8),
}


def make_hdr(flags: int, ocp_ver: int, msg_type: int) -> bytes:
  ocp_byte = (8 << 4) | (ocp_ver & 0x0F)
  return struct.pack('>HBBB', 0x10DE, flags, ocp_byte, msg_type)


def write_zip(path: str, seeds: list[bytes]) -> None:
  with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
    for idx, data in enumerate(seeds):
      digest = hashlib.sha1(data).hexdigest()[:12]
      info = zipfile.ZipInfo(f'seed_{idx:04d}_{digest}.bin')
      info.date_time = (2026, 1, 1, 0, 0, 0)
      info.compress_type = zipfile.ZIP_DEFLATED
      info.external_attr = 0o644 << 16
      zf.writestr(info, data)


def build_common_seeds() -> list[bytes]:
  seeds = []
  # Request (0x80), Response (0x00), Event (0xC0), Event Ack (0x40) in V1 & V2
  for flags in (0x00, 0x40, 0x80, 0xC0):
    for ver in (9, 10):
      for mtype in (0, 1, 4, 5, 6):
        hdr = make_hdr(flags, ver, mtype)
        seeds.append(hdr + b'\x00\x00')
        seeds.append(hdr + b'\x00\x00\x01\x00\x00')
        seeds.append(hdr + b'\x00\x00\x04\x00' + b'\x00' * 4)
        seeds.append(hdr + b'\x00\x00\x08\x00' + b'\x00' * 8)
        seeds.append(hdr + b'\x00\x00\x10\x00' + b'\x00' * 16)
        seeds.append(hdr + b'\x01\x00\x00\x00')
  req_v2 = make_hdr(0x80, 10, 5)
  for _, tail in (
      (0, struct.pack('<HI', 0, 1)),
      (1, struct.pack('<HBBBB', 1, 1, 2, 3, 0)),
      (2, struct.pack('<HBBBB', 2, 1, 0, 0, 1)),
      (3, struct.pack('<HH', 3, 0)),
  ):
    payload = struct.pack('<H', 4) + tail
    cmd_hdr = struct.pack('<BBHH', 0x05, 0, len(payload), 0)
    seeds.append(req_v2 + cmd_hdr + payload)
  gpio_payload = struct.pack('<HH', 5, 0)
  seeds.append(req_v2 + struct.pack('<BBHH', 0x05, 0, len(gpio_payload), 0) +
               gpio_payload)
  return seeds


def build_ei_resp_seeds() -> list[bytes]:
  seeds = []
  resp_v1 = make_hdr(0x00, 9, 5)
  for ei_type, subtype, fault in (
      (4, 0, struct.pack('<HI', 0, 1)),
      (4, 1, struct.pack('<HBBBB', 1, 1, 2, 3, 0)),
      (4, 2, struct.pack('<HBBBB', 2, 1, 0, 0, 1)),
      (4, 3, struct.pack('<HH', 3, 0)),
      (5, 0, struct.pack('<H', 0)),
  ):
    prefix = struct.pack('<HH', ei_type, subtype)
    body = struct.pack('<BBHHH', 0x04, 0, 2 + len(fault), 0, ei_type) + fault
    seeds.append(prefix + resp_v1 + body)
  return seeds


def build_module_seeds(mtype: int, count: int) -> list[bytes]:
  seeds = []
  req_v1 = make_hdr(0x80, 9, mtype)
  req_v2 = make_hdr(0x80, 10, mtype)
  resp_v1 = make_hdr(0x00, 9, mtype)
  resp_v2 = make_hdr(0x00, 10, mtype)
  evt_v1 = make_hdr(0xC0, 9, mtype)

  frames = [
      req_v1 + struct.pack('<BB', 0x01, 4) + b'\x00' * 256,
      req_v1 + struct.pack('<BB', 0x01, 8) + b'\x00' * 256,
      req_v1 + struct.pack('<BB', 0x01, 16) + b'\x00' * 256,
      req_v2 + struct.pack('<BBHH', 0x01, 0, 4, 0) + b'\x00' * 256,
      req_v2 + struct.pack('<BBHH', 0x01, 0, 8, 0) + b'\x00' * 256,
      req_v2 + struct.pack('<BBHH', 0x01, 0, 16, 0) + b'\x00' * 256,
      resp_v1 + struct.pack('<BBH', 0x01, 0, 4) + b'\x00' * 256,
      resp_v1 + struct.pack('<BBH', 0x01, 0, 8) + b'\x00' * 256,
      resp_v1 + struct.pack('<BBH', 0x01, 0, 16) + b'\x00' * 256,
      resp_v1 + struct.pack('<BBH', 0x01, 0, 32) + b'\x00' * 256,
      resp_v1 + struct.pack('<BBH', 0x01, 1, 0) + b'\x00' * 32,
      resp_v2 + struct.pack('<BBHHH', 0x01, 0, 8, 0, 0) + b'\x00' * 256,
      evt_v1 + struct.pack('<BBBHB', 0, 1, 0, 0, 8) + b'\x00' * 256,
      b'\x00' * 256,
  ]
  for sel in range(count):
    sel_byte = bytes([sel & 0xFF])
    for fr in frames:
      seeds.append(sel_byte + fr)
  return seeds


def make_fpga_word_rec(seq: int, opcode: int = 0x01, flags: int = 0x14,
                       data: int = 0x01) -> bytes:
  # IBC2 word completion: result=SUCCESS(2), flags, owner=NSM(2), opcode
  return struct.pack('<4sBBBBQIIII', b'IBC2', 2, flags, 2, opcode, 1, 1, 1,
                     seq, data)


def build_fpga_seeds() -> list[bytes]:
  seeds = []
  # sizeof(struct nsm_fpga_identity) == 24 on 64-bit (4-byte tail padding)
  ident = struct.pack('<QIIII', 1, 1, 1, 1, 0)
  # Mode 0: 32-byte IBC2 control, word, authority, byte & xfer completions
  ctrl_rec = struct.pack('<4sBBBBQIIII', b'IBC2', 0x11, 0, 2, 1, 1, 1, 1, 1, 0)
  word_rec = make_fpga_word_rec(1, opcode=0x01, flags=0x14, data=0x12345678)
  auth_rec = struct.pack('<4sBBBBQIIQ', b'IBC2', 1, 0x23, 0, 0, 1, 0, 0, 0)
  byte_rec = make_fpga_word_rec(1, opcode=0x20, flags=0x54, data=0x42)
  xfer_rec = make_fpga_word_rec(1, opcode=0x49, flags=0x54, data=0x11223344)
  for rec, op, arg in (
      (ctrl_rec, 0x11, 0),
      (word_rec, 0x01, 0),
      (auth_rec, 0x10, 0),
      (byte_rec, 0x20, 0x000D0010),
      (xfer_rec, 0x49, 0x00000010),
  ):
    tail = ident + struct.pack('<BBBIQQ', op, 3, 0x0F, arg, 0, 2)
    seeds.append(b'\x00' + rec + tail)

  # Mode 1: LP30 map/rule/table lookups and numeric/state/identity decoding
  for p_idx in range(5):
    for r_idx in (0, 1, 2, 5, 10):
      hdr = struct.pack('<BBBB I', 1, p_idx, r_idx, 3, 1)
      seeds.append(hdr + b'LP30\x00' + b'\x01\x00\x00\x00' * 8)

  # Mode 2: stateful nsm_fpga_run execution across LP30 rules & control jobs
  replies = b''.join(
      b'\x00' + (b'\x00' + make_fpga_word_rec(seq, opcode=0x01, flags=0x14))
      for seq in range(1, 9)
  )
  for job in range(5):
    for p_idx in range(5):
      seeds.append(struct.pack('<BBBBI', 2, job, p_idx, 0, 0) + replies)
      seeds.append(struct.pack('<BBBBI', 2, job, p_idx, 1, 0) + b'\x00' +
                   auth_rec + replies)
  return seeds


def main() -> None:
  out_dir = sys.argv[1]
  common_seeds = build_common_seeds()

  for bin_path in sorted(glob.glob(os.path.join(out_dir, 'decode_*_fuzzer'))):
    name = os.path.basename(bin_path)
    if name == 'decode_get_error_injection_payload_resp_fuzzer':
      seeds = build_ei_resp_seeds()
    elif name == 'decode_nsm_provide_token_req_fuzzer':
      hdr = make_hdr(0x80, 10, 4)
      seeds = common_seeds + [
          hdr + struct.pack('<BBHH', 0x01, 0, 16, 0) + (b'\x41' * 65535),
          hdr + struct.pack('<BBHH', 0x01, 0, 0, 0) + (b'\x00' * 65535),
      ]
    else:
      seeds = common_seeds
    write_zip(os.path.join(out_dir, f'{name}_seed_corpus.zip'), seeds)

  for name, (mtype, count) in sorted(MODULE_SPECS.items()):
    if os.path.exists(os.path.join(out_dir, name)):
      write_zip(
          os.path.join(out_dir, f'{name}_seed_corpus.zip'),
          build_module_seeds(mtype, count),
      )

  if os.path.exists(os.path.join(out_dir, 'nsm_fpga_fuzzer')):
    write_zip(
        os.path.join(out_dir, 'nsm_fpga_fuzzer_seed_corpus.zip'),
        build_fpga_seeds(),
    )


if __name__ == '__main__':
  main()

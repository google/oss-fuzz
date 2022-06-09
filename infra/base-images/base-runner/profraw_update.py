#!/usr/bin/env python3
# Copyright 2021 Google LLC
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
"""Helper script for upgrading a profraw file to latest version."""

from collections import namedtuple
import struct
import subprocess
import sys

HeaderGeneric = namedtuple('HeaderGeneric', 'magic version')
HeaderVersion7 = namedtuple(
    'HeaderVersion7',
    'BinaryIdsSize DataSize PaddingBytesBeforeCounters CountersSize \
    PaddingBytesAfterCounters NamesSize CountersDelta NamesDelta ValueKindLast')

PROFRAW_MAGIC = 0xff6c70726f667281


def relativize_address(data, offset, databegin, sect_prf_cnts, sect_prf_data):
  """Turns an absolute offset into a relative one."""
  value = struct.unpack('Q', data[offset:offset + 8])[0]
  if sect_prf_cnts <= value < sect_prf_data:
    # If the value is an address in the right section, make it relative.
    value = (value - databegin) & 0xffffffffffffffff
    value = struct.pack('Q', value)
    for i in range(8):
      data[offset + i] = value[i]


def upgrade(data, sect_prf_cnts, sect_prf_data):
  """Upgrades profraw data, knowing the sections addresses."""
  generic_header = HeaderGeneric._make(struct.unpack('QQ', data[:16]))
  if generic_header.magic != PROFRAW_MAGIC:
    raise Exception('Bad magic.')
  if generic_header.version == 5:
    generic_header = generic_header._replace(version=7)
    # Upgrade from version 5 to 7 by adding binaryids field.
    data = data[:8] + struct.pack('Q', generic_header.version) + struct.pack(
        'Q', 0) + data[16:]
  if generic_header.version < 7:
    raise Exception('Unhandled version.')
  if generic_header.version == 7:
    # cf https://reviews.llvm.org/D111123
    generic_header = generic_header._replace(version=8)
    data = data[:8] + struct.pack('Q', generic_header.version) + data[16:]
  v7_header = HeaderVersion7._make(struct.unpack('QQQQQQQQQ', data[16:88]))

  if v7_header.BinaryIdsSize % 8 != 0:
    # Adds padding for binary ids.
    # cf commit b9f547e8e51182d32f1912f97a3e53f4899ea6be
    # cf https://reviews.llvm.org/D110365
    padlen = 8 - (v7_header.BinaryIdsSize % 8)
    v7_header = v7_header._replace(BinaryIdsSize=v7_header.BinaryIdsSize +
                                   padlen)
    data = data[:16] + struct.pack('Q', v7_header.BinaryIdsSize) + data[24:]
    data = data[:88 + v7_header.BinaryIdsSize] + bytes(
        padlen) + data[88 + v7_header.BinaryIdsSize:]

  if v7_header.CountersDelta != (sect_prf_cnts -
                                 sect_prf_data) & 0xffffffffffffffff:
    # Rust linking seems to add an offset...
    sect_prf_data = v7_header.CountersDelta - sect_prf_cnts + sect_prf_data
    sect_prf_cnts = v7_header.CountersDelta

  dataref = sect_prf_data
  relativize_address(data, 64, dataref, sect_prf_cnts, sect_prf_data)

  offset = 88 + v7_header.BinaryIdsSize
  # This also works for C+Rust binaries compiled with
  # clang-14/rust-nightly-clang-13.
  for _ in range(v7_header.DataSize):
    # 16 is the offset of CounterPtr in ProfrawData structure.
    relativize_address(data, offset + 16, dataref, sect_prf_cnts, sect_prf_data)
    # We need this because of CountersDelta -= sizeof(*SrcData);
    # seen in __llvm_profile_merge_from_buffer.
    dataref += 44 + 2 * (v7_header.ValueKindLast + 1)
    # This is the size of one ProfrawData structure.
    offset += 44 + 2 * (v7_header.ValueKindLast + 1)

  return data


def main():
  """Helper script for upgrading a profraw file to latest version."""
  if len(sys.argv) != 4:
    sys.stderr.write('Usage: %s <binary> <profraw> <output>\n' % sys.argv[0])
    return 1

  # First find llvm profile sections addresses in the elf, quick and dirty.
  process = subprocess.Popen(['readelf', '-S', sys.argv[1]],
                             stdout=subprocess.PIPE)
  output, err = process.communicate()
  if err:
    print('readelf failed')
    return 2
  for line in iter(output.split(b'\n')):
    if b'__llvm_prf_cnts' in line:
      sect_prf_cnts = int(line.split()[3], 16)
    elif b'__llvm_prf_data' in line:
      sect_prf_data = int(line.split()[3], 16)

  # Then open and read the input profraw file.
  with open(sys.argv[2], 'rb') as input_file:
    profraw_base = bytearray(input_file.read())
  # Do the upgrade, returning a bytes object.
  profraw_latest = upgrade(profraw_base, sect_prf_cnts, sect_prf_data)
  # Write the output to the file given to the command line.
  with open(sys.argv[3], 'wb') as output_file:
    output_file.write(profraw_latest)

  return 0


if __name__ == '__main__':
  sys.exit(main())

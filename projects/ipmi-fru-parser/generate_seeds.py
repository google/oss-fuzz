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

import os
import sys
import zipfile

def ipmi_checksum(data: bytes) -> int:
    return (-sum(data)) & 0xFF

def create_valid_full_fru() -> bytes:
    # Header: 8 bytes
    # [0] = 0x01 (version)
    # [1] = 0x00 (internal offset)
    # [2] = 0x01 (chassis offset -> byte 8)
    # [3] = 0x02 (board offset -> byte 16)
    # [4] = 0x04 (product offset -> byte 32)
    # [5] = 0x00 (multirecord offset)
    # [6] = 0x00 (pad)
    # [7] = checksum
    hdr_body = bytes([0x01, 0x00, 0x01, 0x02, 0x04, 0x00, 0x00])
    hdr_crc = ipmi_checksum(hdr_body)
    hdr = hdr_body + bytes([hdr_crc])

    # Chassis Area at offset 8 (length 8 bytes = 1 unit)
    chassis_body = bytes([0x01, 0x01, 0x17, 0xC3, ord('A'), ord('B'), ord('C')])
    chassis_crc = ipmi_checksum(chassis_body)
    chassis = chassis_body + bytes([chassis_crc])

    # Board Area at offset 16 (length 16 bytes = 2 units)
    board_body = bytes([
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
        0xC4, ord('O'), ord('P'), ord('E'), ord('N'),
        0xC3, ord('B'), ord('M'), ord('C')
    ])
    board_crc = ipmi_checksum(board_body)
    board = board_body + bytes([board_crc])

    # Product Area at offset 32 (length 16 bytes = 2 units)
    product_body = bytes([
        0x01, 0x02, 0x00,
        0xC4, ord('P'), ord('R'), ord('O'), ord('D'),
        0xC3, ord('V'), ord('1'), ord('0'),
        0xC1, 0x00, 0x00
    ])
    product_crc = ipmi_checksum(product_body)
    product = product_body + bytes([product_crc])

    return hdr + chassis + board + product

def create_chassis_seed() -> bytes:
    return bytes([0x00, 0x00, 0x17, 0xC5, ord('C'), ord('H'), ord('A'), ord('S'), ord('S'), 0xC1])

def create_board_seed() -> bytes:
    return bytes([
        0x00, 0x00, 0x00, 0x10, 0x20, 0x30,
        0xC5, ord('B'), ord('O'), ord('A'), ord('R'), ord('D'),
        0xC4, ord('N'), ord('A'), ord('M'), ord('E'),
        0xC1
    ])

def create_product_seed() -> bytes:
    return bytes([
        0x00, 0x00, 0x00,
        0xC7, ord('P'), ord('R'), ord('O'), ord('D'), ord('U'), ord('C'), ord('T'),
        0xC3, ord('P'), ord('N'), ord('1'),
        0xC1
    ])

def main():
    if len(sys.argv) > 1:
        output_zip = sys.argv[1]
    else:
        output_zip = "fuzz_fru_parser_seed_corpus.zip"

    seeds = {
        "full_fru_1.bin": create_valid_full_fru(),
        "chassis_1.bin": create_chassis_seed(),
        "board_1.bin": create_board_seed(),
        "product_1.bin": create_product_seed(),
    }

    with zipfile.ZipFile(output_zip, "w") as z:
        for name, data in seeds.items():
            z.writestr(name, data)

    print(f"Created {output_zip} with {len(seeds)} seed files.")

if __name__ == "__main__":
    main()

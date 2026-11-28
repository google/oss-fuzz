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
"""Write seed inputs for fuzz-init-sec-context.

Each input is: one configuration byte, then length-prefixed tokens (16-bit,
little endian). The first token is the server's CHALLENGE message (MS-NLMP
2.2.1.2); the optional ones after it are passed to unwrap and verify_mic.
"""
import os
import struct
import sys

NEGOTIATE_UNICODE = 0x00000001
REQUEST_TARGET = 0x00000004
NEGOTIATE_SIGN = 0x00000010
NEGOTIATE_SEAL = 0x00000020
NEGOTIATE_DATAGRAM = 0x00000040
NEGOTIATE_LM_KEY = 0x00000080
NEGOTIATE_NTLM = 0x00000200
NEGOTIATE_ALWAYS_SIGN = 0x00008000
TARGET_TYPE_DOMAIN = 0x00010000
TARGET_TYPE_SERVER = 0x00020000
NEGOTIATE_IDENTIFY = 0x00100000
EXTENDED_SESSIONSECURITY = 0x00080000
NEGOTIATE_TARGET_INFO = 0x00800000
NEGOTIATE_VERSION = 0x02000000
NEGOTIATE_128 = 0x20000000
NEGOTIATE_KEY_EXCH = 0x40000000
NEGOTIATE_56 = 0x80000000

BASE = (NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM |
        NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_TARGET_INFO | NEGOTIATE_VERSION |
        NEGOTIATE_128 | NEGOTIATE_56)
FULL = (BASE | NEGOTIATE_SIGN | NEGOTIATE_SEAL | EXTENDED_SESSIONSECURITY |
        NEGOTIATE_KEY_EXCH)

# Server flag sets: plain, full session security, datagram, identify, and
# old-style LM key without extended session security.
FLAG_SETS = [
    BASE | TARGET_TYPE_SERVER,
    FULL | TARGET_TYPE_SERVER,
    FULL | TARGET_TYPE_DOMAIN | NEGOTIATE_DATAGRAM,
    FULL | TARGET_TYPE_SERVER | NEGOTIATE_IDENTIFY,
    (FULL & ~EXTENDED_SESSIONSECURITY) | NEGOTIATE_LM_KEY |
    TARGET_TYPE_SERVER,
]

# MsvAvId values (MS-NLMP 2.2.2.1)
MSV_AV_EOL = 0
MSV_AV_NB_COMPUTER = 1
MSV_AV_NB_DOMAIN = 2
MSV_AV_DNS_COMPUTER = 3
MSV_AV_DNS_DOMAIN = 4
MSV_AV_DNS_TREE = 5
MSV_AV_FLAGS = 6
MSV_AV_TIMESTAMP = 7


def u16(s):
    return s.encode('utf-16-le')


def av_pair(av_id, value):
    return struct.pack('<HH', av_id, len(value)) + value


def target_info(variant):
    ti = av_pair(MSV_AV_NB_DOMAIN, u16('EXAMPLE'))
    ti += av_pair(MSV_AV_NB_COMPUTER, u16('SERVER'))
    if variant >= 1:
        ti += av_pair(MSV_AV_DNS_DOMAIN, u16('example.com'))
        ti += av_pair(MSV_AV_DNS_COMPUTER, u16('server.example.com'))
        ti += av_pair(MSV_AV_DNS_TREE, u16('example.com'))
    if variant >= 2:
        # 2026-01-01 00:00:00 UTC as a Windows FILETIME
        ti += av_pair(MSV_AV_TIMESTAMP, struct.pack('<Q', 134116992000000000))
        ti += av_pair(MSV_AV_FLAGS, struct.pack('<I', 0))
    return ti + av_pair(MSV_AV_EOL, b'')


def challenge(flags, variant, nonce):
    target_name = u16('EXAMPLE')
    ti = target_info(variant) if flags & NEGOTIATE_TARGET_INFO else b''
    header_len = 56
    msg = b'NTLMSSP\x00' + struct.pack('<I', 2)
    msg += struct.pack('<HHI', len(target_name), len(target_name), header_len)
    msg += struct.pack('<I', flags)
    msg += nonce                                   # server challenge
    msg += b'\x00' * 8                             # reserved
    msg += struct.pack('<HHI', len(ti), len(ti),
                       header_len + len(target_name))
    msg += bytes([10, 0]) + struct.pack('<H', 20348) + b'\x00\x00\x00\x0f'
    return msg + target_name + ti


def token(data):
    return struct.pack('<H', len(data)) + data


def main():
    out = os.path.join(sys.argv[1], 'fuzz-init-sec-context')
    os.makedirs(out, exist_ok=True)
    # NTLM signature: version 1, checksum, sequence number (MS-NLMP 2.2.2.9)
    signature = struct.pack('<I', 1) + bytes(range(8)) + struct.pack('<I', 0)
    n = 0
    for i, flags in enumerate(FLAG_SETS):
        for variant in range(3):
            for cfg in (0x00, 0x03, 0x05, 0x18, 0x9d, 0xfd):
                nonce = bytes((7 * n + k) & 0xff for k in range(8))
                data = bytes([cfg]) + token(challenge(flags, variant, nonce))
                if cfg & 0x18:
                    data += token(signature + b'test')  # unwrap
                    data += token(signature)            # verify_mic
                with open(os.path.join(out, 'seed-%03d' % n), 'wb') as f:
                    f.write(data)
                n += 1


if __name__ == '__main__':
    main()

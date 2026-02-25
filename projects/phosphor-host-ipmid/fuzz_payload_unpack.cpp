// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ipmid/message.hpp>

#include <array>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Need at least selector byte + 1 byte of payload
    if (size < 2)
    {
        return 0;
    }

    // Use first byte to select which path to exercise
    uint8_t selector = data[0];
    data++;
    size--;

    // Create a SecureBuffer from the fuzz input
    ipmi::SecureBuffer buf(data, data + size);

    switch (selector % 16)
    {
        // ========== UNPACK CASES ==========

        case 0:
        {
            // Unpack fundamental types: uint8, uint16, uint32
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint8_t u8 = 0;
            uint16_t u16 = 0;
            uint32_t u32 = 0;
            p.unpack(u8, u16, u32);
            break;
        }
        case 1:
        {
            // Unpack fixed-width bit types
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint3_t bits3{};
            uint4_t bits4{};
            uint5_t bits5{};
            bool flag = false;
            uint7_t bits7{};
            p.unpack(bits3, bits4, flag, bits5, bits7);
            break;
        }
        case 2:
        {
            // Unpack string (UCSD-Pascal style: length-prefixed)
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            std::string str;
            p.unpack(str);
            break;
        }
        case 3:
        {
            // Unpack vector<uint8_t> (consumes remainder)
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            std::vector<uint8_t> vec;
            p.unpack(vec);
            break;
        }
        case 4:
        {
            // Unpack optional types
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint8_t u8 = 0;
            std::optional<uint16_t> optU16;
            std::optional<uint32_t> optU32;
            p.unpack(u8, optU16, optU32);
            break;
        }
        case 5:
        {
            // Unpack array<uint8_t, N>
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            std::array<uint8_t, 4> arr{};
            uint16_t u16 = 0;
            p.unpack(arr, u16);
            break;
        }
        case 6:
        {
            // Unpack bitset
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            std::bitset<8> bs;
            uint8_t u8 = 0;
            p.unpack(bs, u8);
            break;
        }
        case 7:
        {
            // Mixed: bit fields + fundamental (exercises unaligned unpack)
            // Unpacking bit-fields leaves bitCount > 0, then a uint16_t
            // triggers UnpackBytesUnaligned
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint3_t tri{};
            uint16_t u16 = 0;
            uint4_t nib{};
            uint32_t u32 = 0;
            p.unpack(tri, u16, nib, u32);
            break;
        }
        case 8:
        {
            // Unpack into SecureBuffer (remainder drain)
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint8_t u8 = 0;
            ipmi::SecureBuffer sb;
            p.unpack(u8, sb);
            break;
        }
        case 9:
        {
            // Unpack into std::span<const uint8_t> (zero-copy remainder)
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint8_t u8 = 0;
            std::span<const uint8_t> sp;
            p.unpack(u8, sp);
            break;
        }
        case 10:
        {
            // Unpack into a Payload (variable-length handler pattern)
            ipmi::message::Payload p(std::move(buf));
            uint8_t u8 = 0;
            ipmi::message::Payload inner;
            p.unpack(u8, inner);
            // inner is now a copy of the remaining payload
            // Exercise inner unpacking too
            inner.trailingOk = true;
            uint16_t u16 = 0;
            inner.unpack(u16);
            break;
        }
        case 11:
        {
            // Exercise fullyUnpacked(), reset(), re-unpack
            ipmi::message::Payload p(std::move(buf));
            p.trailingOk = true;
            uint8_t u8 = 0;
            p.unpack(u8);
            p.fullyUnpacked();

            // Reset and unpack again from the beginning
            p.reset();
            uint16_t u16 = 0;
            p.unpack(u16);
            p.fullyUnpacked();
            break;
        }

        // ========== PACK CASES ==========

        case 12:
        {
            // Pack bit-fields + integers (exercises appendBits, drain,
            // PackBytesUnaligned)
            ipmi::message::Payload p;
            bool b = (data[0] & 1);
            uint3_t tri = data[0] >> 1;
            uint4_t nib = data[0] >> 4;
            p.pack(b, tri, nib);

            // Now pack a uint16_t while bitCount > 0 (unaligned path)
            uint16_t u16 = 0;
            if (size >= 3)
            {
                std::memcpy(&u16, data + 1, sizeof(u16));
            }
            p.pack(u16);
            p.drain();

            // Pack a string
            size_t strLen = (size > 3) ? std::min<size_t>(data[0] % 64, size - 3)
                                       : 0;
            if (strLen > 0)
            {
                std::string str(reinterpret_cast<const char*>(data + 3), strLen);
                p.pack(str);
            }

            // Pack a vector<uint8_t>
            std::vector<uint8_t> vec(data, data + size);
            p.pack(vec);

            // Verify we can read it back
            p.drain();
            (void)p.size();
            (void)p.data();
            break;
        }
        case 13:
        {
            // Pack bitset, fixed_uint_t, bool combinations
            ipmi::message::Payload p;
            std::bitset<8> bs(data[0]);
            p.pack(bs);

            uint7_t u7 = data[0] & 0x7F;
            bool flag = data[0] >> 7;
            p.pack(u7, flag);

            // Pack a SecureBuffer
            ipmi::SecureBuffer sb(data, data + size);
            p.drain();
            p.pack(sb);

            // Pack a string_view
            std::string_view sv(reinterpret_cast<const char*>(data), size);
            ipmi::message::Payload p2;
            p2.pack(sv);
            break;
        }
        case 14:
        {
            // Pack + unpack round trip with bit fields (mixed alignment)
            ipmi::message::Payload packer;
            bool b1 = data[0] & 1;
            uint3_t tri = (data[0] >> 1) & 0x7;
            uint4_t nib = (data[0] >> 4) & 0xF;
            uint8_t byte = (size > 1) ? data[1] : 0;
            packer.pack(b1, tri, nib, byte);
            packer.drain();

            // Unpack what we just packed
            ipmi::message::Payload unpacker(std::move(packer.raw));
            unpacker.trailingOk = true;
            bool ob1 = false;
            uint3_t otri{};
            uint4_t onib{};
            uint8_t obyte = 0;
            unpacker.unpack(ob1, otri, onib, obyte);
            unpacker.fullyUnpacked();
            break;
        }
        case 15:
        {
            // Prepend and Payload-into-Payload packing
            ipmi::message::Payload p1;
            ipmi::message::Payload p2;

            uint8_t v1 = data[0];
            uint16_t v2 = 0;
            if (size >= 3)
            {
                std::memcpy(&v2, data + 1, sizeof(v2));
            }

            p1.pack(v1);
            p1.drain();
            p2.pack(v2);
            p2.drain();

            // Prepend p1 into p2
            p2.prepend(p1);

            // Pack one payload into another
            ipmi::message::Payload p3;
            p3.pack(v1);
            p3.drain();
            ipmi::message::Payload p4;
            p4.pack(p3);

            // Resize accessor
            p4.resize(p4.size() + 1);

            // Exercise destructor warning path: no trailingOk, no fullyUnpacked
            {
                ipmi::message::Payload pWarn(
                    ipmi::SecureBuffer(data, data + size));
                pWarn.unpackCheck = true; // prevent the lg2 warning
            }
            break;
        }
    }

    return 0;
}

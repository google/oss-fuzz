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
//
////////////////////////////////////////////////////////////////////////////////

#include "tinyxml2/tinyxml2.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

using namespace tinyxml2;

static uint8_t NextByte(const uint8_t *&d, size_t &s) {
    if (s == 0) return 0;
    return (--s, *d++);
}

static uint32_t NextU32(const uint8_t *&d, size_t &s) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | NextByte(d, s);
    return v;
}

static const char *NextStr(const uint8_t *&d, size_t &s, size_t maxLen = 32) {
    static char buf[512];
    if (maxLen >= sizeof(buf)) maxLen = sizeof(buf) - 1;
    size_t n = 0;
    while (n < maxLen && s > 0) {
        char c = static_cast<char>(NextByte(d, s));
        if (c == '\0') break;
        buf[n++] = c;
    }
    buf[n] = '\0';
    return buf;
}

static void FuzzStreamingPrinter(const uint8_t *d, size_t s) {
    bool compact   = (NextByte(d, s) & 1) != 0;
    int  initDepth = static_cast<int>(NextByte(d, s) & 0x0F);
    XMLPrinter::EscapeAposCharsInAttributes apos =
        (NextByte(d, s) & 1) ? XMLPrinter::ESCAPE_APOS_CHARS_IN_ATTRIBUTES
                              : XMLPrinter::DONT_ESCAPE_APOS_CHARS_IN_ATTRIBUTES;

    XMLPrinter printer(nullptr, compact, initDepth, apos);

    printer.PushHeader((NextByte(d, s) & 1) != 0, (NextByte(d, s) & 1) != 0);

    uint8_t numRoots = (NextByte(d, s) % 4) + 1;
    for (uint8_t r = 0; r < numRoots && s > 0; ++r) {
        const char *name = NextStr(d, s, 16);
        if (!name[0]) name = "root";
        bool ec = (NextByte(d, s) & 1) != 0;

        printer.OpenElement(name, ec);

        if (s > 0) printer.PushAttribute("a_str",  NextStr(d, s, 24));
        if (s > 0) printer.PushAttribute("a_int",  static_cast<int>(NextU32(d, s)));
        if (s > 0) printer.PushAttribute("a_uint", static_cast<unsigned>(NextU32(d, s)));
        if (s > 0) printer.PushAttribute("a_i64",  static_cast<int64_t>(NextU32(d, s)));
        if (s > 0) printer.PushAttribute("a_u64",  static_cast<uint64_t>(NextU32(d, s)));
        if (s > 0) printer.PushAttribute("a_bool", (NextByte(d, s) & 1) != 0);
        if (s > 0) printer.PushAttribute("a_dbl",  static_cast<double>(NextU32(d, s)) / 1e6);

        if (s > 0 && (NextByte(d, s) & 1)) {
            const char *child = NextStr(d, s, 12);
            if (!child[0]) child = "c";
            printer.OpenElement(child);

            switch (NextByte(d, s) % 9) {
                case 0: printer.PushText(NextStr(d, s, 32), false);                        break;
                case 1: printer.PushText(NextStr(d, s, 32), true);                         break;
                case 2: printer.PushText(static_cast<int>(NextU32(d, s)));                 break;
                case 3: printer.PushText(static_cast<unsigned>(NextU32(d, s)));            break;
                case 4: printer.PushText(static_cast<int64_t>(NextU32(d, s)));             break;
                case 5: printer.PushText(static_cast<uint64_t>(NextU32(d, s)));            break;
                case 6: printer.PushText((NextByte(d, s) & 1) != 0);                      break;
                case 7: printer.PushText(static_cast<float>(NextU32(d, s))  / 1e5f);      break;
                case 8: printer.PushText(static_cast<double>(NextU32(d, s)) / 1e9);       break;
            }
            printer.CloseElement();
        }

        if (s > 0 && (NextByte(d, s) & 1)) printer.PushComment(NextStr(d, s, 32));
        if (s > 0 && (NextByte(d, s) & 1)) printer.PushDeclaration(NextStr(d, s, 32));
        if (s > 0 && (NextByte(d, s) & 1)) printer.PushUnknown(NextStr(d, s, 32));

        printer.CloseElement(ec);
    }

    (void)printer.CStr();
    (void)printer.CStrSize();

    printer.ClearBuffer(true);
    (void)printer.CStr();
    printer.ClearBuffer(false);
    (void)printer.CStrSize();
}

static void FuzzVisitorPath(const uint8_t *d, size_t s) {
    std::string xml(reinterpret_cast<const char *>(d), s);

    const Whitespace wsModes[] = {
        PRESERVE_WHITESPACE,
        COLLAPSE_WHITESPACE,
        PEDANTIC_WHITESPACE
    };
    for (auto ws : wsModes) {
        for (bool ents : {true, false}) {
            XMLDocument doc(ents, ws);
            if (doc.Parse(xml.c_str()) != XML_SUCCESS) continue;

            XMLPrinter compact(nullptr, true);
            doc.Accept(&compact);
            (void)compact.CStr();

            XMLPrinter pretty(nullptr, false);
            doc.Accept(&pretty);
            (void)pretty.CStr();

            XMLDocument doc2;
            doc2.Parse(pretty.CStr());
        }
    }
}

static void FuzzMixedPrinter(const uint8_t *d, size_t s) {
    XMLPrinter printer(nullptr, false, 0);
    printer.PushDeclaration("xml version=\"1.0\" encoding=\"UTF-8\"");

    uint8_t depth = 0;
    const uint8_t MAX_DEPTH = 8;

    while (s > 0) {
        switch (NextByte(d, s) % 9) {
            case 0:
                if (depth < MAX_DEPTH) {
                    const char *n = NextStr(d, s, 8);
                    printer.OpenElement(n[0] ? n : "e");
                    ++depth;
                }
                break;
            case 1:
                if (depth > 0) { printer.CloseElement(); --depth; }
                break;
            case 2:
                if (depth > 0)
                    printer.PushAttribute(NextStr(d, s, 8), NextStr(d, s, 16));
                break;
            case 3:
                if (depth > 0) printer.PushText(NextStr(d, s, 32), false);
                break;
            case 4:
                if (depth > 0) printer.PushText(NextStr(d, s, 32), true);
                break;
            case 5:
                if (depth > 0) {
                    switch (NextByte(d, s) % 7) {
                        case 0: printer.PushText(static_cast<int>(NextU32(d, s)));        break;
                        case 1: printer.PushText(static_cast<unsigned>(NextU32(d, s)));   break;
                        case 2: printer.PushText(static_cast<int64_t>(NextU32(d, s)));    break;
                        case 3: printer.PushText(static_cast<uint64_t>(NextU32(d, s)));   break;
                        case 4: printer.PushText((NextByte(d, s) & 1) != 0);              break;
                        case 5: printer.PushText(static_cast<float>(NextU32(d, s)) / 1e4f); break;
                        case 6: printer.PushText(static_cast<double>(NextU32(d, s)) / 1e8); break;
                    }
                }
                break;
            case 6:
                printer.PushComment(NextStr(d, s, 24));
                break;
            case 7:
                printer.PushUnknown(NextStr(d, s, 24));
                break;
            case 8:
                while (depth > 0) { printer.CloseElement(); --depth; }
                printer.ClearBuffer(true);
                break;
        }
    }

    while (depth > 0) { printer.CloseElement(); --depth; }
    (void)printer.CStr();
    (void)printer.CStrSize();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    const uint8_t *payload = data + 1;
    size_t psz = size - 1;

    switch (data[0] % 3) {
        case 0: FuzzStreamingPrinter(payload, psz); break;
        case 1: FuzzVisitorPath(payload, psz);      break;
        case 2: FuzzMixedPrinter(payload, psz);     break;
    }
    return 0;
}
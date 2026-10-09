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

"""Structured seed generation for the FreeRADIUS OSS-Fuzz fuzzers.

FreeRADIUS keeps its real fuzzer corpora in git-lfs
(src/tests/fuzzer-corpus/<proto>.tar), but the OSS-Fuzz build does a shallow
clone without `git lfs pull` and never packages them, so the protocol fuzzers
run with *no* seed corpus.  Each protocol fuzzer (fuzzer_radius, fuzzer_dhcpv4,
...) feeds the raw input to that protocol's `*_decode_proto` test point, which
validates and then decodes a full packet into attribute pairs.  The decoders
are dictionary-driven and have a distinct code path per attribute/option/RR
*type*, almost none of which a byte-mutation fuzzer reaches from an empty
corpus.

This script emits structurally valid packets that exercise a broad spread of
those per-type decode paths, one corpus directory per fuzzer:

    radius   full RADIUS packets: header + diverse attribute types (int/ipaddr/
             ipv6/date/ether/ifid/string/octets, VSAs, tagged, extended/long-
             extended/EVS, structural TLVs)
    dhcpv4   BOOTP header + magic cookie + a wide set of DHCP options + RAI TLVs
    dhcpv6   msg-type + xid + options incl. nested IA-NA/IA-Addr and Relay-Fwd
    dns      header + question + many RR types (A/AAAA/CNAME/MX/TXT/SOA/SRV/PTR)
             with name compression
    tacacs   12-byte header + (unencrypted) authen/author/acct bodies
    tftp     RRQ/WRQ/DATA/ACK/ERROR
    vmps     VQP join/reconfirm requests
    bfd      BFD control packets
    cf       FreeRADIUS configuration files (sections, expansions, conditionals)

Pure Python standard library.  Usage:  python3 generate_seeds.py <out_dir>
"""

import os
import sys
import struct


def w(d, name, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("latin-1"))


# ==========================================================================
# RADIUS
# ==========================================================================
def _radius(code, ident, attrs, authenticator=None):
    if authenticator is None:
        authenticator = bytes(range(16))
    body = b"".join(attrs)
    length = 20 + len(body)
    hdr = struct.pack(">BBH", code, ident, length) + authenticator
    return hdr + body


def _attr(t, value):
    return struct.pack(">BB", t, 2 + len(value)) + value


def _vsa(vendor, vtype, value):
    sub = struct.pack(">BB", vtype, 2 + len(value)) + value
    return _attr(26, struct.pack(">I", vendor) + sub)


def gen_radius(base):
    d = os.path.join(base, "radius")
    ip = lambda a, b, c, e: bytes([a, b, c, e])
    i32 = lambda v: struct.pack(">I", v)

    # 1) Access-Request with a broad spread of standard attribute types.
    attrs = [
        _attr(1, b"bob"),                              # User-Name (string)
        _attr(2, bytes(16)),                           # User-Password (encrypted)
        _attr(4, ip(192, 0, 2, 1)),                    # NAS-IP-Address (ipaddr)
        _attr(5, i32(1)),                              # NAS-Port (integer)
        _attr(6, i32(1)),                              # Service-Type (integer)
        _attr(7, i32(1)),                              # Framed-Protocol
        _attr(8, ip(10, 0, 0, 5)),                     # Framed-IP-Address
        _attr(30, b"00-11-22-33-44-55"),               # Called-Station-Id
        _attr(31, b"aa-bb-cc-dd-ee-ff"),               # Calling-Station-Id
        _attr(32, b"nas01"),                           # NAS-Identifier
        _attr(55, i32(0x66000000)),                    # Event-Timestamp (date)
        _attr(61, i32(15)),                            # NAS-Port-Type (integer)
        _attr(80, bytes(16)),                          # Message-Authenticator
    ]
    w(d, "access_request.bin", _radius(1, 0, attrs))

    # 2) Accounting-Request.
    attrs = [
        _attr(40, i32(1)),                             # Acct-Status-Type
        _attr(44, b"session-0001"),                    # Acct-Session-Id
        _attr(45, i32(1)),                             # Acct-Authentic
        _attr(46, i32(120)),                           # Acct-Session-Time
        _attr(42, i32(1024)),                          # Acct-Input-Octets
        _attr(43, i32(2048)),                          # Acct-Output-Octets
        _attr(32, b"nas01"),
    ]
    w(d, "accounting.bin", _radius(4, 1, attrs))

    # 3) Vendor-Specific attributes (Cisco AV-Pair, Microsoft MS-CHAP, WiMAX).
    attrs = [
        _vsa(9, 1, b"shell:priv-lvl=15"),              # Cisco AVPair
        _vsa(311, 11, bytes(16)),                      # MS-CHAP-Challenge
        _vsa(311, 1, bytes(50)),                       # MS-CHAP-Response
        _vsa(24757, 1, i32(1)),                        # WiMAX-ish (continued bit)
        _attr(26, i32(99999) + b"\x01\x06" + i32(7)),  # unknown-vendor VSA
    ]
    w(d, "vsa.bin", _radius(1, 2, attrs))

    # 4) Tagged tunnel attributes + integer/short/byte variety.
    attrs = [
        _attr(64, b"\x01" + b"\x00\x00\x0d"),          # Tunnel-Type (tagged)
        _attr(65, b"\x01" + b"\x00\x00\x01"),          # Tunnel-Medium-Type
        _attr(81, b"\x01group-A"),                     # Tunnel-Private-Group-Id
        _attr(27, i32(600)),                           # Session-Timeout
        _attr(28, i32(300)),                           # Idle-Timeout
        _attr(62, i32(2)),                             # Port-Limit
    ]
    w(d, "tagged.bin", _radius(2, 3, attrs))

    # 5) IPv6 attribute types.
    v6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
    attrs = [
        _attr(95, v6),                                 # NAS-IPv6-Address (ipv6addr)
        _attr(97, b"\x00\x40" + v6[:8]),               # Framed-IPv6-Prefix
        _attr(96, bytes(8)),                           # Framed-Interface-Id (ifid)
        _attr(98, v6),                                 # Login-IPv6-Host
        _attr(168, v6),                                # Framed-IPv6-Address
    ]
    w(d, "ipv6.bin", _radius(1, 4, attrs))

    # 6) Extended / long-extended / EVS attribute formats (241-246).
    attrs = [
        _attr(241, b"\x01" + i32(1)),                  # Extended-Type-1 + ext-type
        _attr(242, b"\x02" + b"hello"),                # Extended-Type-2
        _attr(245, b"\x01\x80" + b"frag1"),            # Long-Extended (More set)
        _attr(245, b"\x01\x00" + b"frag2"),            # Long-Extended (last)
        _attr(241, b"\x1a" + i32(9) + b"\x01" + b"x"), # Extended EVS (ext 26)
    ]
    w(d, "extended.bin", _radius(1, 5, attrs))

    # 7) CoA-Request + State/Class octets + Reply-Message.
    attrs = [
        _attr(24, bytes(8)),                           # State (octets)
        _attr(25, b"class-data"),                      # Class (octets)
        _attr(18, b"Hello, world"),                    # Reply-Message (string)
        _attr(11, b"filter-1"),                        # Filter-Id
        _attr(77, b"CONNECT 54Mbps"),                  # Connect-Info
    ]
    w(d, "coa.bin", _radius(43, 6, attrs))


# ==========================================================================
# DHCPv4
# ==========================================================================
def _dhcpv4(msg_type, options, op=1):
    hdr = struct.pack(">BBBB", op, 1, 6, 0)            # op, htype, hlen, hops
    hdr += struct.pack(">I", 0x12345678)              # xid
    hdr += struct.pack(">HH", 0, 0x8000)              # secs, flags (broadcast)
    hdr += b"\x00" * 16                               # ciaddr/yiaddr/siaddr/giaddr
    hdr += bytes(range(6)) + b"\x00" * 10             # chaddr (16)
    hdr += b"\x00" * 64                               # sname
    hdr += b"\x00" * 128                              # file
    hdr += b"\x63\x82\x53\x63"                        # magic cookie
    opt = struct.pack(">BBB", 53, 1, msg_type)        # DHCP-Message-Type
    opt += options + b"\xff"                          # options + end
    return hdr + opt


def _opt(code, value):
    return struct.pack(">BB", code, len(value)) + value


def gen_dhcpv4(base):
    d = os.path.join(base, "dhcpv4")
    ip = lambda a, b, c, e: bytes([a, b, c, e])
    options = (
        _opt(50, ip(10, 0, 0, 50)) +                  # Requested-IP-Address
        _opt(51, struct.pack(">I", 3600)) +           # Lease-Time
        _opt(54, ip(10, 0, 0, 1)) +                   # Server-Identifier
        _opt(55, bytes([1, 3, 6, 15, 51, 54])) +      # Parameter-Request-List
        _opt(1, ip(255, 255, 255, 0)) +               # Subnet-Mask
        _opt(3, ip(10, 0, 0, 1)) +                    # Router
        _opt(6, ip(8, 8, 8, 8) + ip(8, 8, 4, 4)) +    # DNS-Server (list)
        _opt(12, b"client-host") +                    # Hostname
        _opt(15, b"example.com") +                    # Domain-Name
        _opt(60, b"PXEClient:Arch:00000") +           # Vendor-Class-Identifier
        _opt(61, b"\x01" + bytes(range(6))) +         # Client-Identifier
        # Relay-Agent-Information (82) with circuit-id(1) + remote-id(2) TLVs
        _opt(82, _opt(1, b"eth0:100") + _opt(2, b"relay-1")) +
        # Vendor-Specific (43) sub-options
        _opt(43, _opt(1, b"\x01") + _opt(2, b"boot"))
    )
    w(d, "discover.bin", _dhcpv4(1, options))
    w(d, "request.bin", _dhcpv4(3, options))
    w(d, "ack.bin", _dhcpv4(5, options, op=2))


# ==========================================================================
# DHCPv6
# ==========================================================================
def _d6opt(code, value):
    return struct.pack(">HH", code, len(value)) + value


def gen_dhcpv6(base):
    d = os.path.join(base, "dhcpv6")
    v6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
    duid = struct.pack(">H", 1) + struct.pack(">H", 1) + struct.pack(">I", 0) + \
        bytes(range(6))                               # DUID-LLT
    ia_addr = _d6opt(5, v6 + struct.pack(">II", 3600, 7200))  # IA-Address
    ia_na = _d6opt(3, struct.pack(">III", 1, 1000, 2000) + ia_addr)  # IA-NA
    ia_prefix = _d6opt(26, struct.pack(">IIB", 3600, 7200, 56) + v6)
    ia_pd = _d6opt(25, struct.pack(">III", 2, 1000, 2000) + ia_prefix)
    opts = (
        _d6opt(1, duid) +                             # Client-ID
        _d6opt(2, duid) +                             # Server-ID
        _d6opt(8, struct.pack(">H", 0)) +             # Elapsed-Time
        _d6opt(6, struct.pack(">HHH", 23, 24, 39)) +  # Option-Request
        ia_na + ia_pd +
        _d6opt(23, v6) +                              # DNS-Servers
        _d6opt(39, b"\x00host.example.com")           # Client-FQDN
    )
    # Solicit (1), transaction id (3 bytes)
    w(d, "solicit.bin", b"\x01" + b"\xab\xcd\xef" + opts)
    w(d, "request.bin", b"\x03" + b"\x11\x22\x33" + opts)
    # Relay-Forward (12): hop-count + link-addr + peer-addr + Relay-Message(9)
    inner = b"\x01" + b"\xab\xcd\xef" + opts
    relay = b"\x0c" + b"\x00" + v6 + v6 + _d6opt(9, inner)
    w(d, "relay_forward.bin", relay)


# ==========================================================================
# DNS
# ==========================================================================
def gen_dns(base):
    d = os.path.join(base, "dns")

    def name(labels):
        return b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"

    qname = name(["www", "example", "com"])
    # header: id, flags(QR=1 response, RD/RA), qd=1, an=6, ns=0, ar=1
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 6, 0, 1)
    question = qname + struct.pack(">HH", 1, 1)        # A, IN
    # name compression pointer to qname at offset 12
    ptr = struct.pack(">H", 0xC000 | 12)

    def rr(typ, rdata, n=ptr, ttl=300):
        return n + struct.pack(">HHIH", typ, 1, ttl, len(rdata)) + rdata

    answers = b""
    answers += rr(1, bytes([93, 184, 216, 34]))        # A
    answers += rr(28, bytes([0x20, 1, 0x0d, 0xb8] + [0] * 11 + [1]))  # AAAA
    answers += rr(5, name(["alias", "example", "com"]))   # CNAME
    answers += rr(15, struct.pack(">H", 10) + name(["mail", "example", "com"]))  # MX
    answers += rr(16, bytes([5]) + b"hello")           # TXT
    soa = name(["ns", "example", "com"]) + name(["hostmaster", "example", "com"]) \
        + struct.pack(">IIIII", 1, 3600, 600, 86400, 60)
    answers += rr(6, soa)                              # SOA
    # additional: SRV
    srv = struct.pack(">HHH", 10, 20, 5060) + name(["sip", "example", "com"])
    additional = rr(33, srv)
    w(d, "response.bin", header + question + answers + additional)
    # a query-only packet
    q = struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + question
    w(d, "query.bin", q)


# ==========================================================================
# TACACS+
# ==========================================================================
def _tacacs(pkt_type, seq, body, flags=0x01):
    # version 0xc1 (major 12, minor 1); flags 0x01 = UNENCRYPTED
    hdr = struct.pack(">BBBB", 0xc1, pkt_type, seq, flags)
    hdr += struct.pack(">I", 0x12345678)              # session id
    hdr += struct.pack(">I", len(body))               # length
    return hdr + body


def gen_tacacs(base):
    d = os.path.join(base, "tacacs")
    user, port, rem, data = b"bob", b"console", b"10.0.0.1", b"secret"
    # Authentication START (type 1)
    body = struct.pack(">BBBBBBBB", 1, 1, 1, 1,
                       len(user), len(port), len(rem), len(data))
    body += user + port + rem + data
    w(d, "authen_start.bin", _tacacs(1, 1, body))
    # Authorization REQUEST (type 2)
    args = [b"service=shell", b"cmd=show"]
    body = struct.pack(">BBBBBB", 1, 1, 1, 1, len(user), len(port))
    body += struct.pack(">BB", len(rem), len(args))
    body += bytes(len(a) for a in args)
    body += user + port + rem + b"".join(args)
    w(d, "author.bin", _tacacs(2, 1, body))
    # Accounting REQUEST (type 3)
    body = struct.pack(">BBBBBBB", 0x02, 1, 1, 1, len(user), len(port), len(rem))
    body += struct.pack(">B", len(args))
    body += bytes(len(a) for a in args)
    body += user + port + rem + b"".join(args)
    w(d, "acct.bin", _tacacs(3, 1, body))


# ==========================================================================
# TFTP / VMPS / BFD
# ==========================================================================
def gen_tftp(base):
    d = os.path.join(base, "tftp")
    w(d, "rrq.bin", struct.pack(">H", 1) + b"file.txt\x00octet\x00"
      b"blksize\x00512\x00tsize\x000\x00")
    w(d, "wrq.bin", struct.pack(">H", 2) + b"upload.bin\x00netascii\x00")
    w(d, "data.bin", struct.pack(">HH", 3, 1) + bytes(range(64)))
    w(d, "ack.bin", struct.pack(">HH", 4, 1))
    w(d, "error.bin", struct.pack(">HH", 5, 2) + b"file not found\x00")


def gen_vmps(base):
    d = os.path.join(base, "vmps")
    # VQP: version(1), opcode(1), response(1), error(1), seq(4), then attrs
    def attr(t, v):
        return struct.pack(">IH", t, len(v)) + v
    body = struct.pack(">BBBB", 1, 1, 0, 0) + struct.pack(">I", 0xdeadbeef)
    body += struct.pack(">H", 4)                      # attr count
    body += attr(0x00000c01, b"\x0a\x00\x00\x01")     # client IP
    body += attr(0x00000c02, b"Fa0/1")                # port name
    body += attr(0x00000c03, b"vlan1")                # vlan name
    body += attr(0x00000c06, bytes(range(6)))         # MAC
    w(d, "join_request.bin", body)


def gen_bfd(base):
    d = os.path.join(base, "bfd")
    # ver(3)<<5 | diag(0); flags; detect-mult; length(24)
    pkt = struct.pack(">BBBB", (1 << 5) | 0, 0xC0, 3, 24)
    pkt += struct.pack(">II", 0x11111111, 0x22222222)  # my/your discriminator
    pkt += struct.pack(">III", 1000000, 1000000, 0)    # tx/rx/echo intervals
    w(d, "control.bin", pkt)
    # authenticated variant (auth section appended, A bit set)
    auth = struct.pack(">BBB", 1, 8, 1) + b"\x00" + struct.pack(">I", 0)
    pkt2 = struct.pack(">BBBB", (1 << 5) | 0, 0xC4, 3, 24 + len(auth))
    pkt2 += struct.pack(">II", 0x11111111, 0x22222222)
    pkt2 += struct.pack(">III", 1000000, 1000000, 0) + auth
    w(d, "control_auth.bin", pkt2)


# ==========================================================================
# fuzzer_cf  (FreeRADIUS configuration files)
# ==========================================================================
def gen_cf(base):
    d = os.path.join(base, "cf")
    w(d, "basic.conf",
      "# a configuration file\n"
      "prefix = /usr/local\n"
      "name = \"radiusd\"\n"
      "max_requests = 16384\n"
      "server default {\n"
      "    listen {\n"
      "        type = auth\n"
      "        ipaddr = 127.0.0.1\n"
      "        port = 1812\n"
      "    }\n"
      "    authorize {\n"
      "        update control {\n"
      "            &Cleartext-Password := \"hello\"\n"
      "        }\n"
      "        if (&User-Name == \"bob\") {\n"
      "            reject\n"
      "        }\n"
      "    }\n"
      "}\n")
    w(d, "expansions.conf",
      "foo = bar\n"
      "baz = \"${foo}/sub\"\n"
      "ref = ${server.listen.port}\n"
      "modules {\n"
      "    detail {\n"
      "        filename = ${radacctdir}/%{User-Name}/detail\n"
      "        permissions = 0600\n"
      "    }\n"
      "    pap { }\n"
      "}\n"
      "policy {\n"
      "    rewrite_called { if (1 == 1) { update { } } }\n"
      "}\n")
    w(d, "nested_map.conf",
      "instantiate {\n"
      "    map \"%{sql:SELECT 1}\" {\n"
      "        &reply += \"<%{0}>\"\n"
      "    }\n"
      "    switch &User-Name {\n"
      "        case \"a\" { ok }\n"
      "        case { fail }\n"
      "    }\n"
      "    foreach &Class { update request { &Tmp-Integer-0 := 1 } }\n"
      "}\n")


def gen_cf_extra(base):
    """Richer config files targeting the still-dark parts of cf_file.c /
    cf_util.c (production ~15-18%): every section keyword, ${} reference
    expansion, quoting/escaping, conditionals with operators, casts."""
    d = os.path.join(base, "cf")
    w(d, "unlang.conf",
      "server test {\n"
      "  recv Access-Request {\n"
      "    if (&User-Name == \"a\" && &NAS-Port > 0) { ok }\n"
      "    elsif (&User-Name =~ /^[a-z]+$/) { update reply { &Reply-Message := \"hi\" } }\n"
      "    else { reject }\n"
      "    switch &User-Name {\n"
      "      case \"bob\" { ok }\n"
      "      case { fail }\n"
      "    }\n"
      "    foreach &Class { update request { &Tmp-String-0 := \"%{Foreach-Variable-0}\" } }\n"
      "    redundant { pap chap }\n"
      "    load-balance { ldap sql }\n"
      "    redundant-load-balance { sql1 sql2 }\n"
      "  }\n"
      "}\n")
    w(d, "quoting.conf",
      "a = 'single ${not-expanded} quotes'\n"
      "b = \"double %{User-Name} ${ref}\"\n"
      "c = `echo backtick`\n"
      "d = \"line \\\n  continuation\"\n"
      "e = \"escapes \\t \\n \\\" \\x41\"\n"
      "ref = 1\n"
      "num = 0x1f\n"
      "neg = -42\n"
      "flt = 3.14159\n"
      "ip = 192.0.2.1\n"
      "bool_t = yes\n"
      "bool_f = no\n")
    w(d, "references.conf",
      "outer {\n"
      "  base = /var\n"
      "  inner {\n"
      "    path = ${base}/log\n"
      "    up = ${.base}\n"
      "    deep = ${outer.inner.path}\n"
      "  }\n"
      "}\n"
      "copy = ${outer.inner.deep}\n"
      "clients {\n"
      "  client localhost {\n"
      "    ipaddr = 127.0.0.1\n"
      "    secret = testing123\n"
      "    require_message_authenticator = no\n"
      "  }\n"
      "}\n")
    w(d, "casts_ops.conf",
      "policy {\n"
      "  cond {\n"
      "    if (<integer>&NAS-Port == 1) { ok }\n"
      "    if (&Framed-IP-Address < 10.0.0.255) { ok }\n"
      "    if (\"%{expr:1+2}\" == \"3\") { ok }\n"
      "    if (!&User-Password) { noop }\n"
      "    if ((1 + 2) > 2 || 0) { ok }\n"
      "    map { &reply += &request }\n"
      "    update control {\n"
      "      &Cleartext-Password := \"x\"\n"
      "      &Tmp-Octets-0 := 0xdeadbeef\n"
      "      &Tmp-Integer-0 += 1\n"
      "      &Tmp-IP-Address-0 := 10.0.0.1\n"
      "    }\n"
      "  }\n"
      "}\n")


def gen_cf_advanced(base):
    """Configs targeting the cf_file.c process_* dispatchers and parse_input
    edge cases that the basic seeds miss: subrequest/catch/try/timeout/limit/
    transaction/parallel, $template + templates{}, $INCLUDE/$-INCLUDE, typed
    casts, the full operator matrix, and quoting/regex variants."""
    d = os.path.join(base, "cf")

    # unlang keyword sections (each drives a distinct process_* handler)
    w(d, "unlang_keywords.conf",
      "server s {\n"
      "  recv Access-Request {\n"
      "    subrequest ::Access-Request {\n"
      "      update request { &User-Name := \"sub\" }\n"
      "    }\n"
      "    try { sql }\n"
      "    catch { ok }\n"
      "    timeout 5 { sql }\n"
      "    limit 10 { ldap }\n"
      "    transaction { update reply { &Reply-Message := \"x\" } }\n"
      "    parallel { pap chap }\n"
      "    redundant-load-balance { sql1 sql2 sql3 }\n"
      "    foreach i (&Class[*]) { update request { &Tmp-Integer-0 := \"%{i}\" } }\n"
      "    case { reject }\n"
      "    detach\n"
      "    return\n"
      "  }\n"
      "}\n")

    # $template + templates{} block (process_template, cf_template_merge)
    w(d, "templates.conf",
      "templates {\n"
      "  base_listen {\n"
      "    type = auth\n"
      "    ipaddr = *\n"
      "    port = 1812\n"
      "  }\n"
      "}\n"
      "server default {\n"
      "  listen auth {\n"
      "    $template base_listen\n"
      "    port = 11812\n"
      "  }\n"
      "}\n")

    # $INCLUDE / $-INCLUDE (process_include, cf_expand_file, error paths).
    # The files don't exist in the fuzzer's filesystem, so this drives the
    # include-parsing + open-failure paths (the $- form tolerates failure).
    w(d, "includes.conf",
      "$-INCLUDE /nonexistent/optional.conf\n"
      "$INCLUDE ${confdir}/sub.conf\n"
      "prefix = /usr\n"
      "$-INCLUDE ${prefix}/missing-${prefix}.conf\n"
      "$-INCLUDE wildcard.d/\n")

    # operator matrix + typed casts in update/map (add_pair, parse_type_name)
    w(d, "operators.conf",
      "instantiate {\n"
      "  update {\n"
      "    &control.Cleartext-Password := \"a\"\n"
      "    &reply.Reply-Message = \"b\"\n"
      "    &request.Tmp-Integer-0 += 1\n"
      "    &request.Tmp-Integer-1 -= 2\n"
      "    &reply.Tmp-Octets-0 := 0xAABBCC\n"
      "    &request.Tmp-Cast-0 := (uint32) 5\n"
      "    &request.Tmp-IP-0 := (ipaddr) 10.0.0.1\n"
      "    &reply.Filter-Id !* ANY\n"
      "    &reply.Class =* ANY\n"
      "  }\n"
      "  if (&User-Name =~ /^([a-z]+)@(.*)$/) {\n"
      "    update request { &Stripped-User-Name := \"%{1}\" }\n"
      "  }\n"
      "  elsif (&User-Name !~ /admin/) { ok }\n"
      "  if (&NAS-Port <= 10 && &NAS-Port >= 0) { ok }\n"
      "}\n")

    # comments, blank lines, line continuations, name2 sections, empty bodies
    w(d, "lexical.conf",
      "# full-line comment\n"
      "key = value # trailing comment\n"
      "\n"
      "long = \"a very \\\n      long value\"\n"
      "client 10.0.0.0/24 {\n"
      "    secret = s3cr3t\n"
      "    shortname = net\n"
      "}\n"
      "modules {\n"
      "    eap {\n"
      "        default_eap_type = md5\n"
      "        md5 { }\n"
      "        tls { tls = tls-common }\n"
      "    }\n"
      "    empty { }\n"
      "}\n"
      "thread pool {\n"
      "    start_servers = 5\n"
      "    max_servers = 32\n"
      "}\n")


def gen_cbor(base):
    """fuzzer_cbor: input is an indefinite-length CBOR array (0x9f..0xff) of
    map(1) pairs {attr-number: value}, decoded by fr_cbor_decode_pair against
    the test dictionary. util/cbor.c is 0% in the public report (dedicated
    fuzzer, no corpus, and the 0x9f framing is unreachable by mutation). Each
    pair is emitted as its own one-element-array seed so a decode failure on
    one value never aborts the others. Covers every CBOR major type, the 1/2/
    4/8-byte integer encodings, indefinite lengths, floats, simple values, the
    FreeRADIUS type tags (date=1, ethernet=48, ipv4=52, ipv6=54, tdelta=1002),
    and type-matched values for the test dict's typed attributes."""
    d = os.path.join(base, "cbor")

    def cint(major, n):
        if n < 24:
            return bytes([(major << 5) | n])
        if n < 0x100:
            return bytes([(major << 5) | 24, n])
        if n < 0x10000:
            return bytes([(major << 5) | 25]) + struct.pack(">H", n)
        if n < 0x100000000:
            return bytes([(major << 5) | 26]) + struct.pack(">I", n)
        return bytes([(major << 5) | 27]) + struct.pack(">Q", n)

    U = lambda n: cint(0, n)
    NEG = lambda n: cint(1, n - 1)            # encodes -n
    BYTES = lambda b: cint(2, len(b)) + b
    TEXT = lambda s: cint(3, len(s)) + s.encode()
    ARR = lambda *xs: cint(4, len(xs)) + b"".join(xs)
    MAP1 = lambda k, v: bytes([0xA1]) + k + v
    TAG = lambda t, c: cint(6, t) + c

    def wrap(*pairs):
        return bytes([0x9F]) + b"".join(pairs) + bytes([0xFF])

    seeds = {}

    # --- type-matched values for the test base.dict attribute numbers ---
    matched = {
        1:  TEXT("hello"),                              # string
        2:  U(42),                                      # integer/uint32
        3:  BYTES(bytes([192, 0, 2, 1])),               # ipaddr (octets 4)
        4:  TAG(1, U(0x66000000)),                      # date (tag 1 + epoch)
        6:  BYTES(b"\xde\xad\xbe\xef"),                 # octets
        7:  BYTES(bytes(8)),                            # ifid (octets 8)
        8:  BYTES(bytes([0x20, 1, 0x0d, 0xb8] + [0]*11 + [1])),  # ipv6 (16)
        9:  ARR(U(64), BYTES(bytes(16))),               # ipv6prefix [pfx, 16B]
        10: U(200),                                     # byte
        11: U(1000),                                    # short
        12: BYTES(bytes(range(6))),                     # ether (octets 6)
        13: NEG(5),                                     # signed
        19: U(0x1122334455),                            # uint64
        20: ARR(U(24), BYTES(bytes([10, 0, 0, 0]))),    # ipv4prefix [pfx, 4B]
        21: U(0xdeadbeef),                              # uint32
    }
    for a, v in matched.items():
        seeds["m_attr%02d" % a] = wrap(MAP1(U(a), v))
    # all matched together (well-formed -> exercises the array loop fully)
    seeds["m_all"] = wrap(*[MAP1(U(a), v) for a, v in matched.items()])

    # --- generic value-type spread (attr 2 = integer-ish, but vary value) ---
    generic = {
        "u1": U(10), "u2": U(0x0100), "u4": U(0x010000), "u8": U(0x100000000),
        "neg1": NEG(10), "neg_big": cint(1, 0x010000),
        "bytes": BYTES(b"\x01\x02\x03"), "text": TEXT("abc"),
        "arr": ARR(U(1), U(2), U(3)), "nested_arr": ARR(ARR(U(1)), ARR(U(2))),
        "map": MAP1(U(1), U(2)),
        "f16": bytes([0xF9, 0x3C, 0x00]), "f32": bytes([0xFA, 0x40, 0x49, 0x0F, 0xDB]),
        "f64": bytes([0xFB, 0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18]),
        "true": bytes([0xF5]), "false": bytes([0xF4]), "null": bytes([0xF6]),
        "undef": bytes([0xF7]), "simple": bytes([0xF8, 0xFF]),
        "indef_bytes": bytes([0x5F]) + BYTES(b"ab") + BYTES(b"cd") + bytes([0xFF]),
        "indef_text": bytes([0x7F]) + TEXT("ab") + TEXT("cd") + bytes([0xFF]),
        "indef_arr": bytes([0x9F, 0x01, 0x02, 0xFF]),
        "indef_map": bytes([0xBF]) + U(1) + U(2) + bytes([0xFF]),
        "tag_date": TAG(1, U(1700000000)),
        "tag_ether": TAG(48, BYTES(bytes(range(6)))),
        "tag_ipv4": TAG(52, BYTES(bytes([8, 8, 8, 8]))),
        "tag_ipv6": TAG(54, BYTES(bytes(16))),
        "tag_tdelta": TAG(1002, U(30)),
        "tag_nested": TAG(0, TAG(1, U(1))),
    }
    for name, v in generic.items():
        # apply to several attr numbers so some match a typed attr, others
        # become unknown-typed (derived from the cbor major type)
        for a in (2, 6, 14, 99):
            seeds["g_%s_a%d" % (name, a)] = wrap(MAP1(U(a), v))

    # --- prefix decoders: array(2)=[prefix,octets], tagged + raw, many attrs ---
    v4pfx = ARR(U(24), BYTES(bytes([10, 0, 0, 0])))
    v6pfx = ARR(U(64), BYTES(bytes(16)))
    for a in (3, 8, 9, 20, 14, 99):
        seeds["pfx4_a%d" % a] = wrap(MAP1(U(a), v4pfx))
        seeds["pfx6_a%d" % a] = wrap(MAP1(U(a), v6pfx))
        seeds["pfx4t_a%d" % a] = wrap(MAP1(U(a), TAG(52, v4pfx)))
        seeds["pfx6t_a%d" % a] = wrap(MAP1(U(a), TAG(54, v6pfx)))

    # --- structural: TLV/group (attr 15 = tlv) carrying nested pairs ---
    seeds["tlv"] = wrap(MAP1(U(15), wrap(MAP1(U(1), TEXT("x")))))
    seeds["deep"] = wrap(MAP1(U(15), wrap(MAP1(U(15), wrap(MAP1(U(2), U(1)))))))

    # --- extra decode-side variety: bignum tags, float specials, simple
    #     value range, integer width matrix, group recursion via arrays ---
    seeds["bignum_pos"] = wrap(MAP1(U(2), TAG(2, BYTES(bytes(12)))))   # tag2 bignum
    seeds["bignum_neg"] = wrap(MAP1(U(13), TAG(3, BYTES(bytes(12)))))  # tag3 neg bignum
    seeds["f16_inf"] = wrap(MAP1(U(2), bytes([0xF9, 0x7C, 0x00])))     # +inf half
    seeds["f16_nan"] = wrap(MAP1(U(2), bytes([0xF9, 0x7E, 0x00])))     # nan half
    seeds["f32_neg"] = wrap(MAP1(U(2), bytes([0xFA, 0xC0, 0x00, 0x00, 0x00])))
    for s in (0xE0, 0xF0, 0xF3):                                       # simple value range
        seeds["simple_%02x" % s] = wrap(MAP1(U(2), bytes([s])))
    for w_ in (24, 25, 26, 27):                                        # int width matrix
        n = {24: 0x7f, 25: 0x7fff, 26: 0x7fffffff, 27: 0x7fffffffff}[w_]
        seeds["iw_%d_a2" % w_] = wrap(MAP1(U(2), U(n)))
        seeds["iw_%d_a13" % w_] = wrap(MAP1(U(13), NEG(n & 0xffff)))
    # group/struct as a CBOR array of values (recurses through decode)
    seeds["group_arr"] = wrap(MAP1(U(15), ARR(MAP1(U(1), TEXT("a")),
                                              MAP1(U(2), U(7)))))
    seeds["indef_group"] = wrap(MAP1(U(15), bytes([0x9F]) +
                                    MAP1(U(1), TEXT("z")) + bytes([0xFF])))

    for k, v in seeds.items():
        w(d, k + ".cbor", v)


def gen_json(base):
    """fuzzer_json: byte[0] sets split = data[0]*size/256; first part ->
    json_tokener_parse (json-c json_object.c/json_tokener.c), second part ->
    fr_jpath_parse (jpath.c). Emit JSON-heavy seeds (byte0=0xff) and
    jpath-heavy seeds (byte0=0x00), plus combined."""
    d = os.path.join(base, "json")
    jsons = [
        b'{"a":1,"b":2.5,"c":true,"d":null,"e":false}',
        b'{"nested":{"x":{"y":[1,2,3]}},"arr":[{"k":"v"},[1,[2,[3]]]]}',
        b'[1,2,3,4,5,"six",7.0,8e3,-9,true,false,null]',
        b'{"unicode":"\\u00e9\\u0041\\t\\n\\"\\\\","emoji":"\\ud83d\\ude00"}',
        b'{"big":123456789012345678901234567890,"flt":3.14159e-10,"neg":-0.5}',
        b'{"empty_obj":{},"empty_arr":[],"empty_str":""}',
        b'{"dup":1,"dup":2,"dup":3}',
        b'[' + b','.join([b'{"i":%d}' % i for i in range(20)]) + b']',
        b'{"deep":' * 30 + b'1' + b'}' * 30,
        b'"just a string"',
        b'12345',
        b'true',
        b'3.14',
    ]
    jpaths = [
        b"$.foo",
        b"$.foo.bar.baz",
        b"$['key with space']",
        b"$.store.book[0].title",
        b"$.store.book[*].author",
        b"$..author",
        b"$.store.*",
        b"$..book[2]",
        b"$..book[-1:]",
        b"$..book[:2]",
        b"$..book[0,1]",
        b"$.store.book[?(@.price < 10)]",
        b"$..*",
        b"$",
        b"$.a.b[1].c[*].d",
    ]
    for i, j in enumerate(jsons):
        w(d, "json_%02d.bin" % i, b"\xff" + j)               # json-heavy
    for i, p in enumerate(jpaths):
        w(d, "jpath_%02d.bin" % i, b"\x00" + p)              # jpath-heavy
    # combined: json + NUL-ish split + jpath (mid split byte)
    for i, (j, p) in enumerate(zip(jsons, jpaths)):
        body = j + p
        sel = max(1, min(255, (len(j) + 1) * 256 // (len(body) + 1)))
        w(d, "combo_%02d.bin" % i, bytes([sel]) + body)


def gen_cf_typed(base):
    """Typed foreach (parse_type_name) + absolute optional $INCLUDE (drives the
    cf_file_open path) + name2 sections + more parse_input variety."""
    d = os.path.join(base, "cf")
    w(d, "typed_foreach.conf",
      "policy {\n"
      "  p {\n"
      "    foreach string s (&Class[*]) { update request { &Tmp-String-0 := \"%{s}\" } }\n"
      "    foreach uint32 n (&NAS-Port) { update request { &Tmp-Integer-0 := \"%{n}\" } }\n"
      "    foreach ipaddr a (&Framed-IP-Address[*]) { ok }\n"
      "    foreach octets o (&Class) { ok }\n"
      "  }\n"
      "}\n")
    w(d, "abs_include.conf",
      "$-INCLUDE /nonexistent/abs-optional.conf\n"
      "$-INCLUDE /tmp/also-not-here.conf\n"
      "name = root\n"
      "server foo {\n"
      "  namespace = radius\n"
      "}\n"
      "server bar {\n"
      "  namespace = dhcpv4\n"
      "}\n")


def gen_xlat(base):
    """fuzzer_xlat: byte[0]&3 selects mode, byte[1..] is the xlat format
    string. Targets xlat_tokenize + xlat_builtin/xlat_eval (10%/4.7% in
    production). Each expression is emitted under all 4 modes."""
    d = os.path.join(base, "xlat")
    exprs = [
        "%{User-Name}",
        "%{Reply-Message[*]}",
        "%{request.NAS-IP-Address}",
        "%{control.Cleartext-Password}",
        "%{md5:hello}",
        "%{sha1:hello}",
        "%{sha256:%{User-Name}}",
        "%{hmacmd5:key data}",
        "%{expr:1 + 2 * 3 - (4 / 2) % 3}",
        "%{expr:0x10 & 0x0f | 0x80}",
        "%{tolower:ABCdef}",
        "%{toupper:abcDEF}",
        "%{length:%{User-Name}}",
        "%{strlen:hello world}",
        "%{base64:hello}",
        "%{base64decode:aGVsbG8=}",
        "%{hex:hello}",
        "%{rand:1000}",
        "%{randstr:aaaAAA000!!!}",
        "%{integer:&NAS-Port}",
        "%{string:&Framed-IP-Address}",
        "%{%{User-Name}:-default}",
        "%{User-Name:-%{Calling-Station-Id}}",
        "literal %{User-Name} between %{NAS-Identifier} text",
        "%{escape:a/b c}",
        "%{urlquote:a b&c}",
        "%{pairs:request.[*]}",
        "%(concat:%{User-Name}, -)",
        "%{1 + 1}",
        "%{&Tmp-Integer-0 + 1}",
    ]
    for i, e in enumerate(exprs):
        body = e.encode("latin-1")
        for mode in range(4):
            w(d, "x%02d_m%d.bin" % (i, mode), bytes([mode]) + body)


def gen_value(base):
    """fuzzer_value: byte[0] selects the target fr_type_t, byte[1..] is the
    value string parsed by fr_value_box_from_str. Targets value-box parsing
    for each leaf type."""
    d = os.path.join(base, "value")
    # (type-selector byte spread, value string) — byte[0] is taken mod ntypes
    # inside the harness, so emit each string under a spread of selector bytes.
    values = [
        b"hello world \\t\\n",                          # string
        b"0xdeadbeef00",                                # octets
        b"192.0.2.1",                                   # ipv4 addr
        b"192.0.2.0/24",                                # ipv4 prefix
        b"2001:db8::1",                                 # ipv6 addr
        b"2001:db8::/32",                               # ipv6 prefix
        b"00:11:22:33:44:55",                           # ethernet
        b"01:02:03:04:05:06:07:08",                     # ifid
        b"yes",                                         # bool
        b"255",                                         # uint8
        b"65535",                                       # uint16
        b"4294967295",                                  # uint32
        b"18446744073709551615",                        # uint64
        b"-128",                                        # int8
        b"-2147483648",                                 # int32
        b"3.14159",                                     # float
        b"2026-06-12T03:04:05Z",                        # date
        b"30",                                          # time_delta / short
        b"+10",                                         # signed
        b"1.5e10",                                      # float exp
    ]
    sel = 0
    for v in values:
        for t in range(0, 26, 5):                       # spread selector bytes
            w(d, "v%03d.bin" % sel, bytes([t]) + v)
            sel += 1


def gen_der(base):
    """fuzzer_der: byte[0] selects the root attribute, byte[1..] is a DER
    (ASN.1) payload. Targets the DER decoder (src/protocols/der, dark in
    production). Builds a spread of ASN.1 TLV structures."""
    d = os.path.join(base, "der")

    def tlv(tag, content):
        if len(content) < 0x80:
            ln = bytes([len(content)])
        else:
            b = []
            n = len(content)
            while n:
                b.insert(0, n & 0xff); n >>= 8
            ln = bytes([0x80 | len(b)]) + bytes(b)
        return bytes([tag]) + ln + content

    INT = lambda v: tlv(0x02, v)
    OID = lambda v: tlv(0x06, v)
    SEQ = lambda *c: tlv(0x30, b"".join(c))
    SET = lambda *c: tlv(0x31, b"".join(c))

    # An X.509-ish structure: SEQUENCE { INTEGER, OID, BOOLEAN, OCTET STRING,
    # UTF8String, BIT STRING, SET { ... }, GeneralizedTime, NULL }
    payloads = [
        SEQ(
            INT(b"\x02"),                               # version
            INT(bytes(range(8))),                       # serial
            OID(b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"),  # sha256WithRSA OID
            tlv(0x01, b"\xff"),                          # BOOLEAN true
            tlv(0x04, b"octet-string-data"),            # OCTET STRING
            tlv(0x0c, b"utf8 text \xc3\xa9"),           # UTF8String
            tlv(0x03, b"\x00\xde\xad\xbe\xef"),         # BIT STRING
            SET(INT(b"\x01"), INT(b"\x02")),            # SET OF INTEGER
            tlv(0x17, b"260612030405Z"),                # UTCTime
            tlv(0x18, b"20260612030405Z"),              # GeneralizedTime
            tlv(0x05, b""),                             # NULL
        ),
        SEQ(SEQ(OID(b"\x55\x04\x03"), tlv(0x13, b"example.com"))),  # RDN-ish
        # nested SEQUENCE depth + context tags
        SEQ(tlv(0xa0, INT(b"\x02")), tlv(0xa3, OID(b"\x55\x1d\x0e"))),
        tlv(0x02, bytes(20)),                           # bare INTEGER
        tlv(0x06, b"\x2b\x06\x01\x05\x05\x07\x30\x01"),  # bare OID
    ]
    sel = 0
    for pl in payloads:
        for root in range(6):                           # try each root attr
            w(d, "d%02d_r%d.bin" % (sel, root), bytes([root]) + pl)
        sel += 1


# ==========================================================================
GENERATORS = [gen_radius, gen_dhcpv4, gen_dhcpv6, gen_dns, gen_tacacs,
              gen_tftp, gen_vmps, gen_bfd, gen_cf, gen_cf_extra,
              gen_cf_advanced, gen_cf_typed, gen_cbor, gen_json, gen_xlat, gen_value, gen_der]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fr_seeds"
    os.makedirs(out, exist_ok=True)
    for g in GENERATORS:
        try:
            g(out)
        except Exception as e:                       # keep build robust
            sys.stderr.write("seed %s failed: %s\n" % (g.__name__, e))
    total = sum(len(fs) for _, _, fs in os.walk(out))
    sys.stderr.write("generate_seeds.py: wrote %d seeds under %s\n"
                     % (total, out))


if __name__ == "__main__":
    main()

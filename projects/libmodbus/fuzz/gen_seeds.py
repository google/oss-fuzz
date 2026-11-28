#!/usr/bin/env python3
"""Generate the minimal hand-made seed corpus for fuzz_lm (RFC/spec examples)."""
import os, struct, sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def crc16(b):
    c = 0xFFFF
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return struct.pack("<H", c)


def tcp(tid, slave, pdu):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, slave) + pdu


def rtu(slave, pdu):
    return bytes([slave]) + pdu + crc16(bytes([slave]) + pdu)


# request PDUs (spec examples)
pdus = {
    "rcoils": bytes([1]) + struct.pack(">HH", 0, 8),
    "rdisc": bytes([2]) + struct.pack(">HH", 0, 16),
    "rhold": bytes([3]) + struct.pack(">HH", 0, 4),
    "rinp": bytes([4]) + struct.pack(">HH", 0, 2),
    "w1coil": bytes([5]) + struct.pack(">HH", 3, 0xFF00),
    "w1reg": bytes([6]) + struct.pack(">HH", 2, 0x1234),
    "excst": bytes([7]),
    "wcoils": bytes([15]) + struct.pack(">HHB", 0, 10, 2) + b"\xcd\x01",
    "wregs": bytes([16]) + struct.pack(">HHB", 0, 2, 4) + b"\x00\x0a\x01\x02",
    "slaveid": bytes([17]),
    "mask": bytes([22]) + struct.pack(">HHH", 4, 0x00F2, 0x0025),
    "wr": bytes([23]) + struct.pack(">HHHHB", 0, 3, 1, 2, 4) + b"\x00\xff\x00\xee",
    "badfc": bytes([0x2B, 0x0E, 1, 0]),
}
# geometry: 64 bits / 64 input bits / 64 regs / 64 input regs, all start 0
GEO = bytes([0x2D, 0x2D, 0, 0])


def hdr(mode, slave=1, flags=0):
    return bytes([mode]) + GEO + bytes([slave, flags])


def w(name, data):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)


for name, pdu in pdus.items():
    # direct reply: [lo][flag] + req
    r = tcp(1, 1, pdu)
    w(f"reply_tcp_{name}", hdr(0) + bytes([len(r), 0]) + r)
    r = rtu(1, pdu)
    w(f"reply_rtu_{name}", hdr(1) + bytes([len(r), 1 | (3 << 2)]) + r)
    # truncated variant (direct callers)
    r = tcp(1, 1, pdu)[:-2] if len(pdu) > 2 else tcp(1, 1, pdu)
    w(f"reply_trunc_{name}", hdr(0) + bytes([len(r), 0]) + r)

# server stream: several requests back-to-back (state dependent)
seq = [pdus[k] for k in ("w1reg", "wregs", "rhold", "mask", "wr", "wcoils", "rcoils", "slaveid")]
w("server_tcp_seq", hdr(2) + b"".join(tcp(i + 1, 1, p) for i, p in enumerate(seq)))
w("server_rtu_seq", hdr(3) + b"".join(rtu(1, p) for p in seq))
w("server_rtu_bcast", hdr(3) + rtu(0, pdus["w1reg"]) + rtu(1, pdus["rhold"]))

# client ops: [op][fix][a1][a2][a3][a4][flen] frame
# frame = header placeholder + response PDU; fix=1 repairs tid/slave/crc/length
def cop(op, a, rsp_pdu, rtu_mode, fix=1):
    ph = b"\x01" if rtu_mode else b"\x00" * 7
    f = ph + rsp_pdu
    return bytes([op, fix]) + bytes(a) + bytes([len(f)]) + f


for rtu_mode, mode in ((0, 4), (1, 5)):
    tag = "rtu" if rtu_mode else "tcp"
    ops = [
        cop(0, [0, 0, 0, 7], bytes([1, 1, 0xAA]), rtu_mode),  # read_bits nb=8
        cop(2, [0, 0, 0, 1], bytes([3, 4, 0, 1, 0, 2]), rtu_mode),  # read_regs nb=2
        cop(4, [0, 3, 0, 1], bytes([5]) + struct.pack(">HH", 3, 0xFF00), rtu_mode),
        cop(5, [0, 2, 0x12, 0x34], bytes([6]) + struct.pack(">HH", 2, 0x1234), rtu_mode),
        cop(7, [0, 0, 0, 1], bytes([16]) + struct.pack(">HH", 0, 2), rtu_mode),
        cop(8, [0, 4, 0, 0], bytes([22]) + struct.pack(">HHH", 4, 0, 0), rtu_mode),
        cop(9, [0, 0, 1, 1], bytes([23, 4, 0, 1, 0, 2]), rtu_mode),
        cop(10, [0, 0, 32, 0], bytes([17, 4, 0x11, 0xFF, 0x4C, 0x4D]), rtu_mode),
        cop(11, [0x20, 3, 0, 1], bytes([3, 2, 0, 5]), rtu_mode),
    ]
    w(f"client_{tag}_all", hdr(mode) + b"".join(ops))
    w(f"client_{tag}_exc", hdr(mode) + cop(2, [0, 0, 0, 1], bytes([0x83, 2]), rtu_mode))
    w(f"client_{tag}_raw", hdr(mode) + cop(0, [0, 0, 0, 7], bytes([1, 1, 0xAA]), rtu_mode, fix=0))

# proxy seeds: mode 7, flags bit3 = frontend RTU, bit4 = backend RTU
for fe in (0, 1):
    for be in (0, 1):
        flags = (fe << 3) | (be << 4)
        steps = b""
        for pdu, rsp in ((pdus["rhold"], bytes([3, 8]) + bytes(8)),
                         (pdus["w1reg"], bytes([6]) + struct.pack(">HH", 2, 0x1234)),
                         (pdus["wregs"], bytes([16]) + struct.pack(">HH", 0, 2)),
                         (pdus["rhold"], bytes([0x83, 2]))):
            req = rtu(1, pdu) if fe else tcp(7, 1, pdu)
            ph = b"\x01" if be else b"\x00" * 7
            f = ph + rsp
            steps += bytes([len(req), 1]) + req + bytes([len(f)]) + f
        w(f"proxy_{'rtu' if fe else 'tcp'}_to_{'rtu' if be else 'tcp'}", hdr(7, 1, flags) + steps)

# ctor seeds
def ctor(k, s1, s2=b"", b=(0x05, 0xDC, 0x4E)):
    return bytes([6, k, len(s1), len(s2), b[0], b[1], b[2]]) + s1 + s2

w("ctor_tcp", ctor(0, b"192.168.0.1"))
w("ctor_tcp_pi", ctor(1, b"localhost", b"502"))
w("ctor_rtu", ctor(2, b"/dev/ttyUSB0"))

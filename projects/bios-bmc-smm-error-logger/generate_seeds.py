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
"""Deterministic seed corpus generator for bios-bmc-smm-error-logger rde_fuzz."""

import pathlib
import struct
import sys
import zipfile
import zlib

HEADER_SIZE = 0x30
QUEUE_SIZE = 512
UE_REGION_SIZE = 80
QUEUE_OFFSET = HEADER_SIZE + UE_REGION_SIZE  # 128
MAX_OFFSET = QUEUE_SIZE - QUEUE_OFFSET  # 384
MEMORY_REGION_SIZE = 16384

MAGIC = (1, 2, 3, 4)

FLAG_UE_SWITCH = 1 << 0
FLAG_OVERFLOW = 1 << 1

RDE_CMD_MULTIPART_RECEIVE_RESP = 1
RDE_CMD_OPERATION_INIT_REQ = 2

TRANSFER_START = 0
TRANSFER_MIDDLE = 1
TRANSFER_END = 2
TRANSFER_START_AND_END = 3

OP_INIT_UPDATE = 4

RAW_HEADER_SENTINEL = 0xA5
TIMER_ERROR_SENTINEL = 0x5A


def pack_u24(val: int) -> bytes:
    return struct.pack("<I", val & 0xFFFFFF)[:3]


def build_header(
    *,
    bmc_ver: int = 0,
    bios_ver: int = 0,
    magic: tuple[int, int, int, int] = MAGIC,
    queue_size: int = QUEUE_SIZE,
    ue_size: int = UE_REGION_SIZE,
    bmc_flags: int = 0,
    bmc_read_ptr: int = 0,
    bios_flags: int = 0,
    bios_write_ptr: int = 0,
    reserved2: int = 0,
) -> bytes:
    hdr = bytearray()
    hdr += struct.pack("<II", bmc_ver, bios_ver)
    hdr += struct.pack("<IIII", *magic)
    hdr += pack_u24(queue_size)
    hdr += struct.pack("<H", ue_size)
    hdr += struct.pack("<I", bmc_flags)
    hdr += pack_u24(bmc_read_ptr)
    hdr += b"\x00\x00\x00\x00"
    hdr += struct.pack("<I", bios_flags)
    hdr += pack_u24(bios_write_ptr)
    hdr += struct.pack("<B", reserved2)
    assert len(hdr) == HEADER_SIZE
    return bytes(hdr)


def xor_bytes(data: bytes) -> int:
    acc = 0
    for b in data:
        acc ^= b
    return acc


def wrap_queue_entry(seq_id: int, cmd_type: int, payload: bytes) -> bytes:
    hdr_wo_csum = struct.pack("<HHBB", seq_id, len(payload), 0, cmd_type & 0xFF)
    csum = xor_bytes(hdr_wo_csum) ^ xor_bytes(payload)
    hdr = struct.pack("<HHBB", seq_id, len(payload), csum, cmd_type & 0xFF)
    return hdr + payload


def make_frame(
    entries: list[bytes],
    *,
    ue_payload: bytes = b"",
    bmc_flags: int = 0,
    bios_flags: int = 0,
    start_ptr: int = 0,
    reserved2: int = 0,
) -> bytes:
    queue_area = bytearray(MAX_OFFSET)
    pos = start_ptr
    for entry in entries:
        assert len(entry) <= MAX_OFFSET
        for b in entry:
            queue_area[pos] = b
            pos = (pos + 1) % MAX_OFFSET

    ue_area = bytearray(UE_REGION_SIZE)
    assert len(ue_payload) <= UE_REGION_SIZE
    ue_area[: len(ue_payload)] = ue_payload

    hdr = build_header(
        bmc_flags=bmc_flags,
        bmc_read_ptr=start_ptr,
        bios_flags=bios_flags,
        bios_write_ptr=pos,
        reserved2=reserved2,
    )
    frame = hdr + bytes(ue_area) + bytes(queue_area)
    assert len(frame) == QUEUE_SIZE
    return frame


def make_raw_ue_frame(ue_payload: bytes) -> bytes:
    hdr = build_header(
        ue_size=len(ue_payload),
        bios_flags=FLAG_UE_SWITCH,
        reserved2=RAW_HEADER_SENTINEL,
    )
    frame = hdr + ue_payload
    if len(frame) < QUEUE_SIZE:
        frame += b"\x00" * (QUEUE_SIZE - len(frame))
    assert len(frame) <= MEMORY_REGION_SIZE
    return frame


def rde_multipart_cmd(
    transfer_flag: int,
    resource_id: int,
    data: bytes,
    crc32_val: int | None = None,
) -> bytes:
    hdr = struct.pack("<BBII", 0, transfer_flag, resource_id, len(data))
    out = hdr + data
    if crc32_val is not None:
        out += struct.pack("<I", crc32_val & 0xFFFFFFFF)
    return out


def rde_op_init_cmd(
    resource_id: int,
    payload: bytes,
    *,
    op_type: int = OP_INIT_UPDATE,
    contains_payload: bool = True,
    locator: bytes = b"",
    send_handle: int = 0,
) -> bytes:
    flags = (0x01 if locator else 0x00) | (0x02 if contains_payload else 0x00)
    hdr = struct.pack(
        "<IHBBIBI",
        resource_id,
        1,
        op_type,
        flags,
        send_handle,
        len(locator),
        len(payload),
    )
    return hdr + locator + payload


def dict_transfer_frames(resource_id: int, dict_bytes: bytes) -> list[bytes]:
    crc = zlib.crc32(dict_bytes) & 0xFFFFFFFF
    max_chunk = 340
    if len(dict_bytes) <= max_chunk:
        cmd = rde_multipart_cmd(
            TRANSFER_START_AND_END, resource_id, dict_bytes, crc
        )
        return [
            make_frame(
                [wrap_queue_entry(1, RDE_CMD_MULTIPART_RECEIVE_RESP, cmd)]
            )
        ]

    chunks = [
        dict_bytes[i : i + max_chunk]
        for i in range(0, len(dict_bytes), max_chunk)
    ]
    frames: list[bytes] = []
    for idx, chunk in enumerate(chunks):
        if idx == 0:
            cmd = rde_multipart_cmd(TRANSFER_START, resource_id, chunk)
        elif idx < len(chunks) - 1:
            cmd = rde_multipart_cmd(TRANSFER_MIDDLE, resource_id, chunk)
        else:
            cmd = rde_multipart_cmd(TRANSFER_END, resource_id, chunk, crc)
        frames.append(
            make_frame(
                [wrap_queue_entry(idx + 1, RDE_CMD_MULTIPART_RECEIVE_RESP, cmd)]
            )
        )
    return frames


def nnint(val: int) -> bytes:
    if val < 0x100:
        return struct.pack("<BB", 1, val)
    if val < 0x10000:
        return struct.pack("<BH", 2, val)
    return struct.pack("<BI", 4, val)


def bej_string_prop(seq_val: int, text: str) -> bytes:
    raw = text.encode("utf-8") + b"\x00"
    return nnint(seq_val) + b"\x50" + nnint(len(raw)) + raw


def encode_dummy_simple_pdr(
    *,
    odata_type: str | None = None,
    odata_id: str | None = None,
    item_id: str | None = None,
) -> bytes:
    # Using dummy_simple_dict.bin (root seq=0, Id seq=1) + annotation_dict.bin
    # (@odata.id seq=16 -> (16<<1)|1 = 0x21, @odata.type seq=18 -> (18<<1)|1 = 0x25)
    props: list[bytes] = []
    if odata_type is not None:
        props.append(bej_string_prop((18 << 1) | 1, odata_type))
    if odata_id is not None:
        props.append(bej_string_prop((16 << 1) | 1, odata_id))
    if item_id is not None:
        props.append(bej_string_prop((1 << 1) | 0, item_id))
    body = nnint(len(props)) + b"".join(props)
    root_sflv = nnint(0) + b"\x00" + nnint(len(body)) + body
    pldm_hdr = b"\x00\xf0\xf0\xf1\x00\x00\x00"
    return pldm_hdr + root_sflv


def generate_seeds(libbej_test_dir: pathlib.Path) -> dict[str, bytes]:
    dicts_dir = libbej_test_dir / "dictionaries"
    enc_dir = libbej_test_dir / "encoded"

    annotation_dict = (dicts_dir / "annotation_dict.bin").read_bytes()
    dummy_dict = (dicts_dir / "dummy_simple_dict.bin").read_bytes()
    dummy_enc = (enc_dir / "dummy_simple_enc.bin").read_bytes()

    seeds: dict[str, bytes] = {}

    # 1. Single-frame StartAndEnd dictionary transfer + overflow acknowledgement
    cmd_single_dict = rde_multipart_cmd(
        TRANSFER_START_AND_END,
        1,
        dummy_dict,
        zlib.crc32(dummy_dict) & 0xFFFFFFFF,
    )
    seeds["01_single_dict_and_overflow.bin"] = make_frame(
        [wrap_queue_entry(1, RDE_CMD_MULTIPART_RECEIVE_RESP, cmd_single_dict)],
        bios_flags=FLAG_OVERFLOW,
    )

    # Base frames loading annotation dictionary (resId=0) + dummy_simple (resId=1)
    base_dict_frames = dict_transfer_frames(
        0, annotation_dict
    ) + dict_transfer_frames(1, dummy_dict)

    # 2. Full LogService + 4 LogEntries (exercises saved queue, active queue, and eviction/removeAll)
    log_service_bej = encode_dummy_simple_pdr(
        odata_type="#LogService.v1_1_0.LogService",
        odata_id="/redfish/v1/Systems/system/LogServices/BIOS",
        item_id="BIOS",
    )
    log_entry_bej = encode_dummy_simple_pdr(
        odata_type="#LogEntry.v1_13_0.LogEntry",
        odata_id="/redfish/v1/Systems/system/LogServices/BIOS/Entries/e1",
        item_id="e1",
    )
    op_log_service = wrap_queue_entry(
        10, RDE_CMD_OPERATION_INIT_REQ, rde_op_init_cmd(1, log_service_bej)
    )
    op_log_entry = wrap_queue_entry(
        11, RDE_CMD_OPERATION_INIT_REQ, rde_op_init_cmd(1, log_entry_bej)
    )
    seeds["02_log_service_and_eviction.bin"] = b"".join(
        base_dict_frames
        + [
            make_frame([op_log_service, op_log_entry]),
            make_frame([op_log_entry, op_log_entry, op_log_entry]),
        ]
    )

    # 3. Valid UE log in 80-byte reserved region after dictionaries are loaded
    compact_other_bej = encode_dummy_simple_pdr(
        odata_type="#M.v1.M",
        odata_id="/r/m",
    )
    ue_op_cmd = rde_op_init_cmd(1, compact_other_bej)
    assert len(ue_op_cmd) <= UE_REGION_SIZE
    seeds["03_valid_ue_log_and_dummy_enc.bin"] = b"".join(
        base_dict_frames
        + [
            make_frame(
                [
                    wrap_queue_entry(
                        20,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, dummy_enc),
                    )
                ],
                ue_payload=ue_op_cmd,
                bios_flags=FLAG_UE_SWITCH,
            )
        ]
    )

    # 4. Path validation & error branches in ExternalStorerFileInterface / Writer
    other_valid = encode_dummy_simple_pdr(
        odata_type="#MemoryMetrics.v1_4_1.MemoryMetrics",
        odata_id="/redfish/v1/Systems/system/Memory/dimm0/MemoryMetrics",
    )
    traversal_path = encode_dummy_simple_pdr(
        odata_type="#MemoryMetrics.v1_4_1.MemoryMetrics",
        odata_id="/redfish/v1/../../etc/passwd",
    )
    root_only_path = encode_dummy_simple_pdr(
        odata_type="#MemoryMetrics.v1_4_1.MemoryMetrics",
        odata_id="/",
    )
    no_odata_type = encode_dummy_simple_pdr(item_id="NoType")
    log_svc_no_id = encode_dummy_simple_pdr(
        odata_type="#LogService.v1_1_0.LogService",
        odata_id="/redfish/v1/Systems/system/LogServices/NoId",
    )
    log_svc_no_odata_id = encode_dummy_simple_pdr(
        odata_type="#LogService.v1_1_0.LogService",
        item_id="NoOdataId",
    )
    other_no_odata_id = encode_dummy_simple_pdr(
        odata_type="#MemoryMetrics.v1_4_1.MemoryMetrics",
        item_id="NoOdataId",
    )
    seeds["04_external_storer_edge_cases.bin"] = b"".join(
        base_dict_frames
        + [
            # LogEntry before LogService -> rejected
            make_frame([op_log_entry]),
            # Valid Other PDR written twice (overwrite) + path traversal + root path
            make_frame(
                [
                    wrap_queue_entry(
                        1,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, other_valid),
                    ),
                    wrap_queue_entry(
                        2,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, other_valid),
                    ),
                ]
            ),
            make_frame(
                [
                    wrap_queue_entry(
                        3,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, traversal_path),
                    ),
                    wrap_queue_entry(
                        4,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, root_only_path),
                    ),
                ]
            ),
            make_frame(
                [
                    wrap_queue_entry(
                        5,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, no_odata_type),
                    ),
                    wrap_queue_entry(
                        6,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, log_svc_no_id),
                    ),
                ]
            ),
            make_frame(
                [
                    wrap_queue_entry(
                        7,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, log_svc_no_odata_id),
                    ),
                    wrap_queue_entry(
                        8,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(1, other_no_odata_id),
                    ),
                ]
            ),
        ]
    )

    # 5. Chassis dictionary + encoded payload (fits inside normal circular queue)
    chassis_dict = (dicts_dir / "chassis_dict.bin").read_bytes()
    chassis_enc = (enc_dir / "chassis_enc.bin").read_bytes()
    seeds["05_chassis_bej_decode.bin"] = b"".join(
        dict_transfer_frames(0, annotation_dict)
        + dict_transfer_frames(2, chassis_dict)
        + [
            make_frame(
                [
                    wrap_queue_entry(
                        1,
                        RDE_CMD_OPERATION_INIT_REQ,
                        rde_op_init_cmd(2, chassis_enc, locator=b"\x01\x00"),
                    )
                ],
                start_ptr=300,  # Forces wraparoundRead across end of circular queue!
            )
        ]
    )

    # 6-9. Larger Redfish schemas decoded via UE region after multi-part dictionary load
    for idx, name in enumerate(
        ["network_adapter", "circuit", "drive_oem", "storage"], start=6
    ):
        s_dict = (dicts_dir / f"{name}_dict.bin").read_bytes()
        s_enc = (enc_dir / f"{name}_enc.bin").read_bytes()
        res_id = idx
        seeds[f"0{idx}_{name}_bej_decode.bin"] = b"".join(
            dict_transfer_frames(0, annotation_dict)
            + dict_transfer_frames(res_id, s_dict)
            + [make_raw_ue_frame(rde_op_init_cmd(res_id, s_enc))]
        )

    # 10. Multi-dictionary stream switching resourceId across Start -> Middle -> End + bad CRC invalidation
    multi_stream_data = dummy_dict[:100] + dummy_dict[100:200] + dummy_dict[:80]
    multi_crc = zlib.crc32(multi_stream_data) & 0xFFFFFFFF
    seeds["10_multipart_resource_switch_and_crc.bin"] = b"".join(
        [
            make_frame(
                [
                    wrap_queue_entry(
                        1,
                        RDE_CMD_MULTIPART_RECEIVE_RESP,
                        rde_multipart_cmd(TRANSFER_START, 10, dummy_dict[:100]),
                    ),
                    wrap_queue_entry(
                        2,
                        RDE_CMD_MULTIPART_RECEIVE_RESP,
                        rde_multipart_cmd(
                            TRANSFER_MIDDLE, 10, dummy_dict[100:200]
                        ),
                    ),
                    wrap_queue_entry(
                        3,
                        RDE_CMD_MULTIPART_RECEIVE_RESP,
                        rde_multipart_cmd(TRANSFER_END, 11, dummy_dict[:80], multi_crc),
                    ),
                ]
            ),
            # Overwrite existing dictionary entry + trigger bad CRC invalidation
            make_frame(
                [
                    wrap_queue_entry(
                        4,
                        RDE_CMD_MULTIPART_RECEIVE_RESP,
                        rde_multipart_cmd(
                            TRANSFER_START_AND_END, 10, b"badcrc", 0xDEADBEEF
                        ),
                    )
                ]
            ),
        ]
    )

    # 11. RDE command error paths (invalid cmd, no payload, truncated, unsupported op, overflow, pkt order)
    seeds["11_rde_protocol_errors.bin"] = make_frame(
        [
            wrap_queue_entry(1, 99, b"\x01\x02"),
            wrap_queue_entry(2, RDE_CMD_OPERATION_INIT_REQ, b"\x01\x02"),
            wrap_queue_entry(
                3,
                RDE_CMD_OPERATION_INIT_REQ,
                rde_op_init_cmd(1, b"", contains_payload=False),
            ),
            wrap_queue_entry(
                4,
                RDE_CMD_OPERATION_INIT_REQ,
                rde_op_init_cmd(1, b"abc", op_type=0),
            ),
            wrap_queue_entry(
                5,
                RDE_CMD_OPERATION_INIT_REQ,
                rde_op_init_cmd(1, b"abc", send_handle=1),
            ),
            wrap_queue_entry(
                6,
                RDE_CMD_OPERATION_INIT_REQ,
                rde_op_init_cmd(99, b"abc"),
            ),
            wrap_queue_entry(7, RDE_CMD_MULTIPART_RECEIVE_RESP, b"\x00"),
            wrap_queue_entry(
                8,
                RDE_CMD_MULTIPART_RECEIVE_RESP,
                rde_multipart_cmd(TRANSFER_MIDDLE, 1, b"early"),
            ),
            wrap_queue_entry(
                9,
                RDE_CMD_MULTIPART_RECEIVE_RESP,
                rde_multipart_cmd(TRANSFER_END, 1, b"early", 0),
            ),
            wrap_queue_entry(
                10,
                RDE_CMD_MULTIPART_RECEIVE_RESP,
                rde_multipart_cmd(99, 1, b"badflag"),
            ),
            wrap_queue_entry(
                11,
                RDE_CMD_MULTIPART_RECEIVE_RESP,
                rde_multipart_cmd(TRANSFER_START_AND_END, 1, b""),
            ),
        ]
    )

    # 12. Dictionary count cap (maxDictionaries=64) and state-transition edge cases
    cap_frames: list[bytes] = []
    batch: list[bytes] = []
    for res_id in range(1, 65):
        flag = TRANSFER_START if res_id == 1 else TRANSFER_MIDDLE
        batch.append(
            wrap_queue_entry(
                res_id,
                RDE_CMD_MULTIPART_RECEIVE_RESP,
                rde_multipart_cmd(flag, res_id, b"d"),
            )
        )
        if len(batch) == 16:
            cap_frames.append(make_frame(batch))
            batch = []
    cap_frames.append(
        make_frame(
            [
                # Start on existing entry (res_id=1) succeeds -> RdeStateStartRecvd
                wrap_queue_entry(
                    70,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_START, 1, b"d"),
                ),
                # Middle on new res_id=65 fails startDictionaryEntry (>=64), sets prevDictResourceId=65
                wrap_queue_entry(
                    71,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_MIDDLE, 65, b"d"),
                ),
                # Second Middle on res_id=65 hits addDictionaryData(65) -> Resource ID not found
                wrap_queue_entry(
                    72,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_MIDDLE, 65, b"d"),
                ),
                # End on res_id=65 hits addDictionaryData(65) + markDataComplete(65) -> not found
                wrap_queue_entry(
                    73,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_END, 65, b"d", 0),
                ),
                # Start(1) then End(66) hits startDictionaryEntry failure in handleFlagEnd
                wrap_queue_entry(
                    74,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_START, 1, b"d"),
                ),
                wrap_queue_entry(
                    75,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_END, 66, b"d", 0),
                ),
                # Start(67) and StartAndEnd(68) hit startDictionaryEntry failures directly
                wrap_queue_entry(
                    76,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_START, 67, b"d"),
                ),
                wrap_queue_entry(
                    77,
                    RDE_CMD_MULTIPART_RECEIVE_RESP,
                    rde_multipart_cmd(TRANSFER_START_AND_END, 68, b"d", 0),
                ),
            ]
        )
    )
    seeds["12_dictionary_limit_and_transitions.bin"] = b"".join(cap_frames)

    # 13-17. Individual corrupt CircularBufferHeader & timer error seeds
    seeds["13_raw_bad_queue_size.bin"] = build_header(
        queue_size=1024, reserved2=RAW_HEADER_SENTINEL
    ) + (b"\x00" * (QUEUE_SIZE - HEADER_SIZE))
    seeds["14_raw_zero_ue_size.bin"] = build_header(
        ue_size=0, bios_flags=FLAG_UE_SWITCH, reserved2=RAW_HEADER_SENTINEL
    ) + (b"\x00" * (QUEUE_SIZE - HEADER_SIZE))
    seeds["15_raw_oversize_ue_region.bin"] = build_header(
        ue_size=20000, bios_flags=FLAG_UE_SWITCH, reserved2=RAW_HEADER_SENTINEL
    ) + (b"\x00" * (QUEUE_SIZE - HEADER_SIZE))
    seeds["16_raw_bad_write_ptr.bin"] = build_header(
        bios_write_ptr=MAX_OFFSET + 10, reserved2=RAW_HEADER_SENTINEL
    ) + (b"\x00" * (QUEUE_SIZE - HEADER_SIZE))
    seeds["17_raw_bad_read_ptr_and_timer_err.bin"] = make_frame(
        [], reserved2=TIMER_ERROR_SENTINEL
    ) + build_header(
        bmc_read_ptr=MAX_OFFSET + 10, reserved2=RAW_HEADER_SENTINEL
    ) + (
        b"\x00" * (QUEUE_SIZE - HEADER_SIZE)
    )

    return seeds


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <libbej_test_dir> <output_zip>",
            file=sys.stderr,
        )
        return 1

    libbej_test_dir = pathlib.Path(sys.argv[1])
    output_zip = pathlib.Path(sys.argv[2])

    seeds = generate_seeds(libbej_test_dir)
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(seeds):
            info = zipfile.ZipInfo(filename=name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, seeds[name])

    print(f"Wrote {len(seeds)} seeds to {output_zip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

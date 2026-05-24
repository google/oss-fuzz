#!/usr/bin/python3
# Copyright 2025 Google LLC
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

from __future__ import annotations

import sys
import zipfile

from onnx import TensorProto, helper


def _make_model(op_type: str, opset_version: int, inputs: list[str], attrs=None) -> bytes:
    if attrs is None:
        attrs = {}

    graph_inputs = []
    if "X" in inputs:
        graph_inputs.append(helper.make_tensor_value_info("X", TensorProto.FLOAT, [1]))
    if "scales" in inputs:
        graph_inputs.append(
            helper.make_tensor_value_info("scales", TensorProto.FLOAT, [1])
        )

    graph_outputs = [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])]
    node = helper.make_node(op_type, inputs, ["Y"], **attrs)
    graph = helper.make_graph([node], f"{op_type.lower()}-seed", graph_inputs, graph_outputs)
    model = helper.make_model(
        graph,
        producer_name="oss-fuzz",
        opset_imports=[helper.make_opsetid("", opset_version)],
    )
    return model.SerializeToString()


def main() -> int:
    output_zip = sys.argv[1]
    seeds = {
        "cast_9_missing_input.onnx": _make_model("Cast", 9, [], {"to": TensorProto.FLOAT}),
        "softmax_12_missing_input.onnx": _make_model("Softmax", 12, []),
        "softmax_13_missing_input.onnx": _make_model("Softmax", 13, []),
        "upsample_6_missing_input.onnx": _make_model("Upsample", 6, []),
        "upsample_9_missing_scales.onnx": _make_model("Upsample", 9, ["X"]),
        "upsample_9_valid.onnx": _make_model("Upsample", 9, ["X", "scales"]),
    }

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as corpus:
        for name, data in seeds.items():
            corpus.writestr(name, data)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

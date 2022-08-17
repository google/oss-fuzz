// Copyright 2019 Google LLC
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

#include "wabt/src/binary-reader-objdump.h"
#include "wabt/src/binary-reader.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wabt::ObjdumpOptions objdump_options{};
  wabt::ObjdumpState state;

  objdump_options.debug = false;
  objdump_options.filename = "dummy";
  objdump_options.log_stream = nullptr;

  objdump_options.mode = wabt::ObjdumpMode::Prepass;
  wabt::ReadBinaryObjdump(data, size, &objdump_options, &state);

  objdump_options.mode = wabt::ObjdumpMode::Headers;
  wabt::ReadBinaryObjdump(data, size, &objdump_options, &state);

  objdump_options.mode = wabt::ObjdumpMode::Details;
  wabt::ReadBinaryObjdump(data, size, &objdump_options, &state);

  objdump_options.mode = wabt::ObjdumpMode::Disassemble;
  wabt::ReadBinaryObjdump(data, size, &objdump_options, &state);

  objdump_options.mode = wabt::ObjdumpMode::RawData;
  wabt::ReadBinaryObjdump(data, size, &objdump_options, &state);

  return 0;
}


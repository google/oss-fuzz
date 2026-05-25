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

#include <cstddef>
#include <cstdint>

#include <fuzzer/FuzzedDataProvider.h>

#include "wabt/binary-reader-ir.h"
#include "wabt/binary-reader.h"
#include "wabt/binary-writer.h"
#include "wabt/decompiler.h"
#include "wabt/ir.h"
#include "wabt/option-parser.h"
#include "wabt/stream.h"
#include "wabt/validator.h"
#include "wabt/wat-writer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  wabt::Errors errors;
  wabt::Module module;
  wabt::Features features;
  FuzzedDataProvider data_provider(data, size);
#define WABT_FEATURE(variable, flag, default_, help) \
  if (data_provider.ConsumeBool()) { features.enable_##variable(); }
#include "wabt/feature.def"
#undef WABT_FEATURE
  // Add only feature related options, but no logging, stop_on_first_error, etc.
  wabt::ReadBinaryOptions options(features, nullptr, false, false, false);
  std::vector<uint8_t> text = data_provider.ConsumeRemainingBytes<uint8_t>();
  if (wabt::Succeeded(wabt::ReadBinaryIr("", text.data(), text.size(), options, &errors, &module))) {
    wabt::ValidateOptions validate_options(features);
    if (wabt::Succeeded(wabt::ValidateModule(&module, &errors, validate_options))) {
      wabt::DecompileOptions decompile_options;
      wabt::Decompile(module, decompile_options);

      wabt::MemoryStream stream;
      wabt::WriteBinaryOptions write_binary_options;
      wabt::WriteBinaryModule(&stream, &module, write_binary_options);

      wabt::WriteWatOptions write_wat_options(features);
      wabt::WriteWat(&stream, &module, write_wat_options);
    }
  }
  return 0;
}


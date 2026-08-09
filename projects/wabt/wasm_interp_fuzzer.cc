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

#include <cstddef>
#include <cstdint>
#include <vector>

#include "wabt/interp/binary-reader-interp.h"
#include "wabt/binary-reader.h"
#include "wabt/interp/interp.h"
#include "wabt/interp/interp-util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wabt::Errors errors;
  wabt::Features features;
  // Enable all features for more coverage.
#define WABT_FEATURE(variable, flag, default_, help) features.enable_##variable();
#include "wabt/feature.def"
#undef WABT_FEATURE

  wabt::interp::Store store;
  store.setFeatures(features);

  wabt::interp::ModuleDesc module_desc;
  wabt::ReadBinaryOptions options(features, nullptr, true, true, true);
  if (wabt::Succeeded(wabt::interp::ReadBinaryInterp("<fuzzer>", data, size, options, &errors, &module_desc))) {
    // Check for excessive memory allocation to avoid OOM.
    for (auto&& mem : module_desc.memories) {
      if (mem.type.limits.initial > 1024) {
        return 0;
      }
    }

    wabt::interp::Module::Ptr module = wabt::interp::Module::New(store, module_desc);
    wabt::interp::RefVec imports;
    
    // Bind dummy imports
    for (auto&& import : module->desc().imports) {
      if (import.type.type->kind == wabt::interp::ExternKind::Func) {
        auto func_type = *wabt::cast<wabt::interp::FuncType>(import.type.type.get());
        auto host_func = wabt::interp::HostFunc::New(
            store, func_type,
            [](wabt::interp::Thread& thread, const wabt::interp::Values& params,
               wabt::interp::Values& results, wabt::interp::Trap::Ptr* trap) -> wabt::Result {
              return wabt::Result::Ok;
            });
        imports.push_back(host_func.ref());
      } else {
        imports.push_back(wabt::interp::Ref::Null);
      }
    }

    wabt::interp::Instance::Ptr instance;
    wabt::interp::Trap::Ptr trap;
    instance = wabt::interp::Instance::Instantiate(store, module.ref(), imports, &trap);
    if (instance) {
      // Run all exported functions that have no parameters.
      // This is a simple way to exercise the interpreter without complex argument generation.
      for (auto&& export_ : module->desc().exports) {
        if (export_.type.type->kind == wabt::ExternalKind::Func) {
          auto* func_type = wabt::cast<wabt::interp::FuncType>(export_.type.type.get());
          if (func_type->params.empty()) {
            auto func = store.UnsafeGet<wabt::interp::Func>(instance->funcs()[export_.index]);
            wabt::interp::Values params;
            wabt::interp::Values results;
            wabt::interp::Trap::Ptr call_trap;
            func->Call(store, params, results, &call_trap);
          }
        }
      }
    }
  }

  return 0;
}

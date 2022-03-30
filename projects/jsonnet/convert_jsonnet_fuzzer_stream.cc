// Copyright 2022 Google Inc.
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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" {
#include "libjsonnet.h"
}

char* ImportCallback(void* ctx, const char* base, const char* rel,
                     char** found_here, int* success) {
  // Don't load file and mark it as failure.
  *success = 0;
  char* res = jsonnet_realloc(static_cast<struct JsonnetVm*>(ctx), nullptr, 1);
  res[0] = 0;
  return res;
}

std::string ConvertJsonnetToJson(const std::string& jsonnet) {
  JsonnetVm* jvm = jsonnet_make();
  jsonnet_import_callback(jvm, ImportCallback, jvm);
  int error = 0;
  char* res =
      jsonnet_evaluate_snippet_stream(jvm, /*filename=*/"", jsonnet.c_str(), &error);

  std::string json;
  if (error == 0 && res != nullptr) {
    json = res;
  }

  if (res) {
    jsonnet_realloc(jvm, res, 0);
  }
  jsonnet_destroy(jvm);
  return json;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string fuzz_jsonnet(reinterpret_cast<const char*>(data), size);
  ConvertJsonnetToJson(fuzz_jsonnet);
  return 0;
}

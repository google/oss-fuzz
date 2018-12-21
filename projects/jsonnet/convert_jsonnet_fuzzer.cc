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
      jsonnet_evaluate_snippet(jvm, /*filename=*/"", jsonnet.c_str(), &error);

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

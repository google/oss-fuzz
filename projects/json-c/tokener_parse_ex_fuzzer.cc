#include <stdint.h>

#include <json.h>

extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  json_tokener *tok = json_tokener_new();
  json_tokener_parse_ex(tok, data, size);
  json_tokener_free(tok);
  return 0;
}

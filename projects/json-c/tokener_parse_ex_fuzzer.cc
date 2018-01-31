#include <stdint.h>

#include <json.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *data1 = reinterpret_cast<const char *>(data);
  json_tokener *tok = json_tokener_new();
  json_object *obj = json_tokener_parse_ex(tok, data1, size);

  json_object_put(obj);
  json_tokener_free(tok);
  return 0;
}

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "heimbase.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  // Creat null-terminated string
  char *null_terminated = (char *)malloc(size + 1);
  memcpy(null_terminated, (char *)data, size);
  null_terminated[size] = '\0';

  heim_error_t error = NULL;
  heim_object_t o = heim_json_create(null_terminated, 20, 0, &error);
  if (error == NULL) {
    heim_error_t error2 = NULL;
    heim_object_t o2 = heim_json_copy_serialize(o, 0, &error2);
    if (error2 == NULL) {
      heim_error_t error3 = NULL;
      heim_object_t o3 =
          heim_json_create(heim_string_get_utf8(o2), 20, 0, &error3);
      if (error3 != NULL) {
        heim_json_eq(o, o3);
      }
    }
    heim_release(o2);
  }
  heim_release(o);

  free(null_terminated);
  return 0;
}

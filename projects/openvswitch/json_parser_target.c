#include "openvswitch/json.h"
#include "jsonrpc.h"
#include <string.h>
#include <assert.h>
#include "ovsdb-error.h"
#include "ovsdb/table.h"

static void
print_and_free_json(struct json *json)
{
    char *string = json_to_string(json, JSSF_SORT);
    json_destroy(json);
    puts(string);
    free(string);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((size == 0) || (data[size-1] != '\0')) return 0;

    struct json *j1,*j2;
    struct jsonrpc_msg *msg;

    // j1 alloc
    j1 = json_from_string((const char *)data);
    if (j1->type == JSON_STRING) {
      json_destroy(j1);
      return 0;
    // j1 freed
    }
   
    // s1 alloc
    char *s1 = json_to_string(j1, JSSF_SORT | JSSF_PRETTY);

    // frees j1
    char *error = jsonrpc_msg_from_json(j1, &msg);
    if (error) {
      free(s1);
      free(error);
      return 0;
      // j1 freed by API call, s1 freed by hand
    }
   
    // j2 alloc, msg freed
    j2 = jsonrpc_msg_to_json(msg);
    if (j2->type == JSON_STRING) {
      json_destroy(j2);
      free(s1);
      return 0;
      // j2,s1 freed
    }

    // s2 alloc
    char *s2 = json_to_string(j2, JSSF_SORT | JSSF_PRETTY);
    json_destroy(j2);

    free(s1);
    free(s2);

    return 0;
    // j2,s1,s2 freed
}
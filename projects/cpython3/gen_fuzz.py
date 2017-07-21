"""Generate a fuzz test.

`gen_fuzz.py fuzz_test_file.inc fuzz_test_name` will output the fuzz test to stdout.
"""
import os
import sys

FUZZ_TEMPLATE = """
#include <Python.h>
#include <stdlib.h>
#include <inttypes.h>

%(fuzz_definition)s

// CPython generates a lot of leak warnings for whatever reason.
int __lsan_is_turned_off() { return 1; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!Py_IsInitialized()) Py_InitializeEx(0);

  int rv = %(fuzz_test_name)s((const char*)data, size);
  if (PyErr_Occurred()) {
    // Fuzz tests should handle expected errors for themselves.
    PyErr_Print();
    abort();
  }
  return rv;
}
"""

def main(argv):
    if len(argv) != 3:
        sys.exit('Expected exactly two argument: gen_fuzz.py <fuzz_test_include> <fuzz_test_name>')
    unused_argv0, fuzz_test_path, fuzz_test_name = argv
    try:
        fuzz_file = open(fuzz_test_path)
    except IOError as e:
        sys.exit(e)
    with fuzz_file:
        fuzz_definition = fuzz_file.read()
    print (FUZZ_TEMPLATE % {
        'fuzz_definition': fuzz_definition,
        'fuzz_test_name': fuzz_test_name,
    })

if __name__ == '__main__':
    main(sys.argv)

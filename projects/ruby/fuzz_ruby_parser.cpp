/* Copyright 2025 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for Ruby's parser (ruby_parser.c)
 * Tests parsing of Ruby source code with malformed/random input
 * to find bugs in the Ruby parser implementation.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"
#include "ruby/ruby.h"
#include "ruby/encoding.h"

/* Forward declarations for parser functions */
extern "C" {
extern VALUE rb_parser_new(void);
extern VALUE rb_parser_compile_string(VALUE vparser, const char *f, VALUE s, int line);
extern VALUE ruby_verbose;
}

/* Silence stderr output during fuzzing */
static VALUE
silenced_parse(VALUE parser_str_pair)
{
    VALUE *args = (VALUE *)parser_str_pair;
    VALUE parser = args[0];
    VALUE code_str = args[1];
    
    /* Compile the string - this will parse it */
    return rb_parser_compile_string(parser, "(fuzz)", code_str, 1);
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initialized = 0;
    int state;
    
    if (!initialized) {
        ruby_init();
        ruby_init_loadpath();
        initialized = 1;
        
        // Suppress Ruby warnings to avoid log noise
        ruby_verbose = Qfalse;
    }
    
    if (size == 0) {
        return 0;
    }
    
    // Limit input size to avoid pathologically slow parsing
    // Ruby parser can be exponentially slow with deeply nested
    // structures resulting in timeouts.
    if (size > 50000) {
        return 0;
    }
    // Use FuzzedDataProvider for structured data consumption
    FuzzedDataProvider fdp(data, size);
    
    /* Create a Ruby string from the fuzz input */
    std::string code_data = fdp.ConsumeRemainingBytesAsString();
    VALUE code_str = rb_str_new(code_data.data(), code_data.size());
    
    /* Create a new parser instance */
    VALUE parser = rb_parser_new();
    if (NIL_P(parser)) {
        return 0;
    }
    
    /* Prepare arguments for protected call */
    VALUE args[2];
    args[0] = parser;
    args[1] = code_str;
    
    /* Parse the code with exception protection */
    rb_protect(silenced_parse, (VALUE)args, &state);
    
    /* If an exception occurred, clear it and continue */
    if (state) {
        rb_set_errinfo(Qnil);
    }
    
    /* Force GC to clean up */
    rb_gc_start();
    
    return 0;
}

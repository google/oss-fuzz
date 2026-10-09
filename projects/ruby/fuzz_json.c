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
 * Fuzzer for Ruby's JSON parser (ext/json)
 * Tests JSON parsing with malformed/corrupted input
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "ruby.h"
#include "../ruby/ext/json/json.h"
#include "../ruby/ext/json/vendor/ryu.h"
#include "../ruby/ext/json/parser/parser.c"

static int ruby_initialized = 0;

// External declaration for ruby_verbose
extern VALUE ruby_verbose;

// JSON parser wrapper - parses JSON string with default config
static VALUE json_fuzzer_parse(VALUE json_str) {
    JSON_ParserConfig config = {
        .on_load_proc = Qfalse,
        .decimal_class = Qfalse,
        .decimal_method_id = 0,
        .on_duplicate_key = JSON_RAISE,
        .max_nesting = 100,
        .allow_nan = 0,
        .allow_trailing_comma = 0,
        .symbolize_names = 0,
        .freeze = 0
    };
    
    return cParser_parse(&config, json_str);
}

// Test JSON parsing with fuzzer input
static VALUE call_json_parse(VALUE arg) {
    VALUE json_str = (VALUE)arg;
    VALUE result = json_fuzzer_parse(json_str);
    
    // Access the result to ensure it was properly parsed
    if (!NIL_P(result)) {
        rb_funcall(result, rb_intern("class"), 0);
        
        if (RB_TYPE_P(result, T_HASH)) {
            rb_funcall(result, rb_intern("keys"), 0);
        } else if (RB_TYPE_P(result, T_ARRAY)) {
            rb_funcall(result, rb_intern("size"), 0);
        }
    }
    
    return result;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!ruby_initialized) {
        ruby_init();
        ruby_initialized = 1;
        
        // Suppress Ruby warnings to avoid log noise
        ruby_verbose = Qfalse;
    }
    
    if (size == 0) {
        return 0;
    }
    
    VALUE json_str = rb_str_new((const char *)data, size);
    
    int state = 0;
    rb_protect(call_json_parse, json_str, &state);
    
    if (state) {
        rb_set_errinfo(Qnil);
    }
    
    rb_gc_start();
    
    return 0;
}

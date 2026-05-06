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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"
#include "ruby/encoding.h"

static int ruby_initialized = 0;

// Wrapper functions for rb_protect since it needs VALUE (*)(VALUE) signature
static VALUE call_str_dump(VALUE str) { return rb_str_dump(str); }
static VALUE call_str_inspect(VALUE str) { return rb_str_inspect(str); }
static VALUE call_str_length(VALUE str) { return rb_str_length(str); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize Ruby once on first call
    if (!ruby_initialized) {
        ruby_init();
        ruby_initialized = 1;
        
        // Suppress Ruby warnings to avoid log noise
        ruby_verbose = Qfalse;
    }
    
    if (size == 0) return 0;
    
    // Use FuzzedDataProvider for structured data consumption
    FuzzedDataProvider fdp(data, size);
    
    int state = 0;
    
    // Create string from fuzzer data
    std::string str_data = fdp.ConsumeRemainingBytesAsString();
    VALUE str1 = rb_str_new(str_data.data(), str_data.size());
    
    // Test various string operations that might have security implications
    rb_protect(call_str_dump, str1, &state);
    if (state) { rb_set_errinfo(Qnil); state = 0; }
    
    rb_protect(call_str_inspect, str1, &state);
    if (state) { rb_set_errinfo(Qnil); state = 0; }
    
    rb_protect(call_str_length, str1, &state);
    if (state) { rb_set_errinfo(Qnil); state = 0; }
    
    // Test substring operations
    if (str_data.size() > 1) {
        VALUE substr = rb_str_substr(str1, 0, str_data.size() / 2);
        (void)substr; // Suppress unused warning
    }
    
    // Test encoding operations
    rb_enc_associate(str1, rb_utf8_encoding());
    rb_enc_associate(str1, rb_ascii8bit_encoding());
    
    // Clean up - force GC to release memory
    rb_gc_start();
    
    return 0;
}

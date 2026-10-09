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
 * Fuzzer for Ruby's Array#pack and String#unpack (pack.c)
 * 
 * Purpose: Test binary packing/unpacking with various template directives
 * to find bugs in template parsing, data conversion, and boundary handling.
 * 
 * Coverage:
 * - Template parsing: All pack directives (C, S, L, Q, c, s, l, q, A, a, Z, etc.)
 * - Array#pack: Convert Ruby objects to binary string
 * - String#unpack: Parse binary data according to template
 * - Round-trip: pack → unpack consistency
 * - Edge cases: Invalid templates, buffer overflows, encoding issues
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"

static int ruby_initialized = 0;

extern "C" VALUE ruby_verbose;

// Test Array#pack with fuzzer-provided template
static VALUE call_array_pack(VALUE arg) {
    VALUE *args = (VALUE *)arg;
    VALUE ary = args[0];
    VALUE template_str = args[1];
    
    // Call Array#pack with the template
    // This exercises the pack template parser and binary packing logic
    VALUE result = rb_funcall(ary, rb_intern("pack"), 1, template_str);
    
    // Try to use the result to ensure it's valid
    if (!NIL_P(result)) {
        rb_funcall(result, rb_intern("length"), 0);
        rb_funcall(result, rb_intern("encoding"), 0);
    }
    
    return result;
}

// Test String#unpack with fuzzer-provided template and data
static VALUE call_string_unpack(VALUE arg) {
    VALUE *args = (VALUE *)arg;
    VALUE str = args[0];
    VALUE template_str = args[1];
    
    // Call String#unpack with the template
    // This exercises the unpack template parser and binary unpacking logic
    VALUE result = rb_funcall(str, rb_intern("unpack"), 1, template_str);
    
    // Try to iterate the result to ensure it's valid
    if (!NIL_P(result) && RB_TYPE_P(result, T_ARRAY)) {
        long len = RARRAY_LEN(result);
        for (long i = 0; i < len && i < 10; i++) {
            (void)rb_ary_entry(result, i);  // Suppress unused warning
        }
    }
    
    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize Ruby once on first call
    if (!ruby_initialized) {
        ruby_init();
        ruby_initialized = 1;
        
        // Suppress Ruby warnings to avoid log noise
        ruby_verbose = Qfalse;
    }
    
    if (size < 2) {
        return 0;
    }
    
    // Use FuzzedDataProvider for structured data consumption
    FuzzedDataProvider fdp(data, size);
    
    // Split input: template and binary data
    size_t template_len = fdp.ConsumeIntegralInRange<size_t>(1, 10000);
    std::string template_data = fdp.ConsumeBytesAsString(template_len);
    size_t binary_data_len = fdp.ConsumeIntegralInRange<size_t>(1, 10000);
    std::string binary_data = fdp.ConsumeBytesAsString(binary_data_len);
    
    VALUE template_str = rb_str_new(template_data.data(), template_data.size());
    VALUE binary_str = rb_str_new(binary_data.data(), binary_data.size());
    
    int state = 0;
    
    // Test String#unpack with fuzzer data
    VALUE unpack_args[] = {binary_str, template_str};
    rb_protect(call_string_unpack, (VALUE)unpack_args, &state);
    if (state) {
        rb_set_errinfo(Qnil);
        state = 0;
    }
    
    // Test Array#pack with fuzzer template and randomized array data
    VALUE test_array = rb_ary_new();
    
    // Add various Ruby objects with random data from fuzzer
    rb_ary_push(test_array, INT2FIX(fdp.ConsumeIntegral<int16_t>()));
    rb_ary_push(test_array, INT2FIX(fdp.ConsumeIntegral<int16_t>()));
    rb_ary_push(test_array, LONG2NUM(fdp.ConsumeIntegral<int32_t>()));
    rb_ary_push(test_array, rb_float_new(fdp.ConsumeFloatingPoint<double>()));
    
    size_t str1_len = fdp.ConsumeIntegralInRange<size_t>(0, 10000);
    std::string str1 = fdp.ConsumeBytesAsString(str1_len);
    rb_ary_push(test_array, rb_str_new(str1.data(), str1.size()));
    
    size_t str2_len = fdp.ConsumeIntegralInRange<size_t>(0, 10000);
    std::string str2 = fdp.ConsumeBytesAsString(str2_len);
    rb_ary_push(test_array, rb_str_new(str2.data(), str2.size()));
    
    if (fdp.remaining_bytes() >= 8) {
        rb_ary_push(test_array, UINT2NUM(fdp.ConsumeIntegral<uint32_t>()));
        rb_ary_push(test_array, UINT2NUM(fdp.ConsumeIntegral<uint32_t>()));
    }
    
    VALUE pack_args[] = {test_array, template_str};
    rb_protect(call_array_pack, (VALUE)pack_args, &state);
    if (state) {
        rb_set_errinfo(Qnil);
    }
    
    // Test round-trip: pack then unpack
    VALUE packed = Qnil;
    state = 0;
    packed = rb_protect(call_array_pack, (VALUE)pack_args, &state);
    
    if (state == 0 && !NIL_P(packed)) {
        VALUE roundtrip_args[] = {packed, template_str};
        state = 0;
        rb_protect(call_string_unpack, (VALUE)roundtrip_args, &state);
        if (state) {
            rb_set_errinfo(Qnil);
        }
    } else if (state) {
        rb_set_errinfo(Qnil);
    }
    
    // Force GC
    rb_gc_start();
    
    return 0;
}

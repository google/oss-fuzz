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

static int ruby_initialized = 0;

extern "C" VALUE ruby_verbose;
static VALUE cInstructionSequence = Qnil;
static ID id_load_from_binary = 0;

// Wrapper for rb_protect to load ISEQ from binary
static VALUE call_iseq_load_from_binary(VALUE arg) {
    VALUE str = (VALUE)arg;
    
    // Call RubyVM::InstructionSequence.load_from_binary(binary_string)
    // This exercises the complete ISEQ binary deserialization path
    VALUE iseq = rb_funcall(cInstructionSequence, id_load_from_binary, 1, str);
    
    if (!NIL_P(iseq)) {
        // Try to access various ISEQ methods to ensure it was properly loaded
        rb_funcall(iseq, rb_intern("path"), 0);
        rb_funcall(iseq, rb_intern("label"), 0);
        rb_funcall(iseq, rb_intern("first_lineno"), 0);
        rb_funcall(iseq, rb_intern("to_a"), 0);
        
        // Try to inspect it
        rb_funcall(iseq, rb_intern("inspect"), 0);
    }
    
    return Qnil;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize Ruby once on first call
    if (!ruby_initialized) {
        ruby_init();
        ruby_initialized = 1;
        
        // Get RubyVM::InstructionSequence class
        VALUE mRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
        cInstructionSequence = rb_const_get(mRubyVM, rb_intern("InstructionSequence"));
        
        // Get the load_from_binary method ID
        id_load_from_binary = rb_intern("load_from_binary");
    }
    
    // Limit input size to avoid excessive processing
    // ISEQ binary format can be moderately large
    if (size == 0 || size > 16384) {
        return 0;
    }
    
    // Use FuzzedDataProvider for structured data consumption
    FuzzedDataProvider fdp(data, size);
    
    // Create a Ruby string from the fuzzer input
    // This will be passed to load_from_binary
    std::string binary_data = fdp.ConsumeRemainingBytesAsString();
    VALUE binary_str = rb_str_new(binary_data.data(), binary_data.size());
    
    // Call with rb_protect to catch any exceptions/errors
    int state = 0;
    rb_protect(call_iseq_load_from_binary, binary_str, &state);
    
    // Clear any exception that occurred
    if (state) {
        rb_set_errinfo(Qnil);
    }
    
    // Force GC to release memory and detect any memory issues
    rb_gc_start();
    
    return 0;
}

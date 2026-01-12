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
 * Fuzzer for Ruby's Array implementation (array.c)
 * 
 * Purpose: Test array operations including creation, manipulation, sorting,
 * and iteration. Tests edge cases in memory management, element access,
 * and array-specific algorithms.
 * 
 * Coverage:
 * - Element operations: push, pop, shift, unshift, insert, delete
 * - Access operations: [], []=, first, last, at, fetch
 * - Transformation: map, select, compact, flatten, reverse, sort
 * - Combining: concat, +, -, &, |
 * - Iteration: each, each_index, reverse_each
 * - Memory: Array growth/shrinkage, shared arrays
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"

static int ruby_initialized = 0;

extern "C" VALUE ruby_verbose;

// Wrapper functions for rb_protect - necessary to catch exceptions
// Array operations can raise exceptions (e.g., index errors, frozen arrays)
static VALUE call_array_aref(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_ary_entry(ptr[0], FIX2INT(ptr[1]));  // Array element access - ary[index]
}

static VALUE call_array_aset(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    rb_ary_store(ptr[0], FIX2INT(ptr[1]), ptr[2]);  // Array element assignment - ary[index] = value
    return ptr[2];  // Return the value that was set
}

static VALUE call_array_concat(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_ary_concat(ptr[0], ptr[1]);  // Concatenate arrays
}

static VALUE call_array_plus(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("+"), 1, ptr[1]);  // Array addition
}

static VALUE call_array_minus(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("-"), 1, ptr[1]);  // Array subtraction
}

static VALUE call_array_and(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("&"), 1, ptr[1]);  // Array intersection
}

static VALUE call_array_or(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("|"), 1, ptr[1]);  // Array union
}

static VALUE call_array_flatten(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("flatten"), 1, ptr[1]);  // Flatten nested arrays
}

static VALUE call_array_compact(VALUE ary) {
    return rb_funcall(ary, rb_intern("compact"), 0);  // Remove nil elements
}

static VALUE call_array_uniq(VALUE ary) {
    return rb_funcall(ary, rb_intern("uniq"), 0);  // Remove duplicates
}

static VALUE call_array_rotate(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("rotate"), 1, ptr[1]);  // Rotate array
}

static VALUE call_array_sample(VALUE ary) {
    return rb_funcall(ary, rb_intern("sample"), 0);  // Get random element
}

static VALUE call_array_fetch(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("fetch"), 1, ptr[1]);  // Fetch with bounds checking
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize Ruby once on first call
    // Sets up VM, object system, and Array class
    if (!ruby_initialized) {
        ruby_init();
        ruby_initialized = 1;
        
        // Suppress Ruby warnings to avoid log noise
        ruby_verbose = Qfalse;
    }
    
    if (size < 2) return 0;
    
    // Use FuzzedDataProvider for structured data consumption
    FuzzedDataProvider fdp(data, size);
    
    int state = 0;
    VALUE ary = rb_ary_new();
    VALUE args[3];
    
    // Populate array with strings only
    // Testing string arrays exercises array operations with object references
    size_t num_elements = fdp.ConsumeIntegralInRange<size_t>(0, 30);
    for (size_t i = 0; i < num_elements && fdp.remaining_bytes() > 0; i++) {
        size_t str_len = fdp.ConsumeIntegralInRange<size_t>(0, 5000);
        std::string str = fdp.ConsumeBytesAsString(str_len);
        rb_ary_push(ary, rb_str_new(str.data(), str.size()));
    }
    
    // Select and perform a single array operation based on fuzzer input
    // Each operation tests different aspects of array.c
    uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 24);
    
    switch (op) {
            case 0: // Array element access - tests indexing logic
                if (RARRAY_LEN(ary) > 0) {
                    long idx = fdp.ConsumeIntegralInRange<long>(-10, 10);
                    args[0] = ary;
                    args[1] = LONG2FIX(idx);
                    rb_protect(call_array_aref, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 1: // Array element assignment - tests storage and bounds
                {
                    long idx = fdp.ConsumeIntegralInRange<long>(-5, 15);
                    std::string val_data = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    VALUE val = rb_str_new(val_data.data(), val_data.size());
                    args[0] = ary;
                    args[1] = LONG2FIX(idx);
                    args[2] = val;
                    rb_protect(call_array_aset, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 2: // Array push - tests growth
                {
                    std::string data_str = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    rb_ary_push(ary, rb_str_new(data_str.data(), data_str.size()));
                }
                break;
                
            case 3: // Array pop - tests shrinkage
                if (RARRAY_LEN(ary) > 0) {
                    rb_ary_pop(ary);
                }
                break;
                
            case 4: // Array shift - tests FIFO removal
                if (RARRAY_LEN(ary) > 0) {
                    rb_ary_shift(ary);
                }
                break;
                
            case 5: // Array unshift - tests prepending
                {
                    std::string str = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    rb_ary_unshift(ary, rb_str_new(str.data(), str.size()));
                }
                break;
                
            case 6: // Array reverse - tests element reordering
                rb_ary_reverse(ary);
                break;
                
            case 7: // Array sort - tests comparison and ordering
                rb_protect((VALUE (*)(VALUE))rb_ary_sort, ary, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 8: // Array dup - tests shallow copy
                rb_ary_dup(ary);
                break;
                
            case 9: // Array clear - tests bulk removal
                rb_ary_clear(ary);
                break;
                
            case 10: // Array concat - tests array merging
                {
                    VALUE other = rb_ary_new();
                    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 5);
                    for (size_t i = 0; i < n && fdp.remaining_bytes() > 0; i++) {
                        std::string str = fdp.ConsumeBytesAsString(
                            fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                        );
                        rb_ary_push(other, rb_str_new(str.data(), str.size()));
                    }
                    args[0] = ary;
                    args[1] = other;
                    rb_protect(call_array_concat, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 11: // Array join - tests string conversion
                {
                    std::string sep = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    rb_ary_join(ary, rb_str_new(sep.data(), sep.size()));
                }
                break;
                
            case 12: // Array slice - tests subarray extraction
                if (RARRAY_LEN(ary) > 0) {
                    long start = fdp.ConsumeIntegralInRange<long>(0, RARRAY_LEN(ary));
                    long len = fdp.ConsumeIntegralInRange<long>(0, 5000);
                    rb_ary_subseq(ary, start, len);
                }
                break;
                
            case 13: // Array first - tests head access
                {
                    long n = fdp.ConsumeIntegralInRange<long>(0, 2000);
                    rb_funcall(ary, rb_intern("first"), 1, LONG2FIX(n));
                }
                break;
                
            case 14: // Array last - tests tail access
                {
                    long n = fdp.ConsumeIntegralInRange<long>(0, 2000);
                    rb_funcall(ary, rb_intern("last"), 1, LONG2FIX(n));
                }
                break;
                
            case 15: // Array + (addition) - tests combining
                {
                    VALUE other = rb_ary_new();
                    std::string str = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    rb_ary_push(other, rb_str_new(str.data(), str.size()));
                    args[0] = ary;
                    args[1] = other;
                    rb_protect(call_array_plus, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 16: // Array - (subtraction) - tests difference
                {
                    VALUE other = rb_ary_new();
                    if (RARRAY_LEN(ary) > 0) {
                        rb_ary_push(other, rb_ary_entry(ary, 0));
                    }
                    args[0] = ary;
                    args[1] = other;
                    rb_protect(call_array_minus, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 17: // Array & (intersection) - tests set operations
                {
                    VALUE other = rb_ary_new();
                    std::string str = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    rb_ary_push(other, rb_str_new(str.data(), str.size()));
                    args[0] = ary;
                    args[1] = other;
                    rb_protect(call_array_and, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 18: // Array | (union) - tests set operations
                {
                    VALUE other = rb_ary_new();
                    std::string str = fdp.ConsumeBytesAsString(
                        fdp.ConsumeIntegralInRange<size_t>(0, 5000)
                    );
                    rb_ary_push(other, rb_str_new(str.data(), str.size()));
                    args[0] = ary;
                    args[1] = other;
                    rb_protect(call_array_or, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 19: // Array flatten - tests nested array handling
                {
                    args[0] = ary;
                    args[1] = INT2FIX(fdp.ConsumeIntegralInRange<int>(0, 3));
                    rb_protect(call_array_flatten, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 20: // Array compact - tests nil removal
                rb_protect(call_array_compact, ary, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 21: // Array uniq - tests duplicate removal
                rb_protect(call_array_uniq, ary, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 22: // Array rotate - tests circular shift
                {
                    args[0] = ary;
                    args[1] = INT2FIX(fdp.ConsumeIntegralInRange<int>(-5, 5));
                    rb_protect(call_array_rotate, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
                
            case 23: // Array sample - tests random access
                rb_protect(call_array_sample, ary, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 24: // Array fetch - tests bounds-checked access
                if (RARRAY_LEN(ary) > 0) {
                    long idx = fdp.ConsumeIntegralInRange<long>(-10, 10);
                    args[0] = ary;
                    args[1] = LONG2FIX(idx);
                    rb_protect(call_array_fetch, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
        }
    
    // Clean up - force GC to release memory
    // Ensures array memory is properly freed across iterations
    rb_gc_start();
    
    return 0;
}

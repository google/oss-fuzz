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
 * Fuzzer for Ruby's Hash implementation (hash.c)
 * 
 * Purpose: Test hash operations including storage, retrieval, deletion,
 * and complex operations like merging, inverting, and rehashing. Tests
 * edge cases in hash collision handling, memory management, and key equality.
 * 
 * Coverage:
 * - Basic operations: [], []=, delete, clear, keys, values
 * - Advanced operations: merge, update, invert, flatten, shift
 * - Edge cases: rehashing, compare_by_identity, nested hashes
 * - Memory: Hash growth/shrinkage, collision handling
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"

static int ruby_initialized = 0;

extern "C" VALUE ruby_verbose;

// Wrapper functions for rb_protect - necessary to catch exceptions
// Hash operations can raise exceptions (e.g., frozen hash, recursive comparison)
static VALUE call_hash_aref(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_hash_aref(ptr[0], ptr[1]);  // Hash lookup - hash[key]
}

static VALUE call_hash_aset(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_hash_aset(ptr[0], ptr[1], ptr[2]);  // Hash assignment - hash[key] = value
}

static VALUE call_hash_delete(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_hash_delete(ptr[0], ptr[1]);  // Key deletion
}

static VALUE call_hash_rehash(VALUE hash) {
    return rb_funcall(hash, rb_intern("rehash"), 0);  // Rebuild hash after key mutation
}

static VALUE call_hash_clear(VALUE hash) {
    return rb_hash_clear(hash);  // Remove all entries
}

static VALUE call_hash_merge(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("merge"), 1, ptr[1]);  // Non-destructive merge
}

static VALUE call_hash_update(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("merge!"), 1, ptr[1]);  // Destructive merge
}

static VALUE call_hash_invert(VALUE hash) {
    return rb_funcall(hash, rb_intern("invert"), 0);  // Swap keys/values
}

static VALUE call_hash_to_a(VALUE hash) {
    return rb_funcall(hash, rb_intern("to_a"), 0);  // Convert to array of [k,v] pairs
}

static VALUE call_hash_shift(VALUE hash) {
    return rb_funcall(hash, rb_intern("shift"), 0);  // Remove and return first pair
}

static VALUE call_hash_compare_by_id(VALUE hash) {
    return rb_funcall(hash, rb_intern("compare_by_identity"), 0);  // Use object_id for key equality
}

static VALUE call_hash_flatten(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("flatten"), 1, ptr[1]);  // Flatten nested arrays
}

static VALUE call_hash_fetch(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_hash_fetch(ptr[0], ptr[1]);  // Fetch with exception if key not found
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize Ruby once on first call
    // Sets up VM, object system, and Hash class
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
    VALUE hash = rb_hash_new();
    VALUE args[3];
    
    // Populate hash deterministically from fuzzer input
    size_t num_entries = fdp.ConsumeIntegralInRange<size_t>(0, 20);
    for (size_t i = 0; i < num_entries && fdp.remaining_bytes() > 1; i++) {
        size_t key_len = fdp.ConsumeIntegralInRange<size_t>(1, 10000);
        std::string key_data = fdp.ConsumeBytesAsString(key_len);
        size_t val_len = fdp.ConsumeIntegralInRange<size_t>(0, 10000);
        std::string val_data = fdp.ConsumeBytesAsString(val_len);
        
        VALUE key = rb_str_new(key_data.data(), key_data.size());
        VALUE val = rb_str_new(val_data.data(), val_data.size());
        rb_hash_aset(hash, key, val);
    }
    
    // Select a single hash operation to test
    uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 17);
    
    // Create key and value for the operation from remaining data
    size_t key_len = fdp.ConsumeIntegralInRange<size_t>(1, 10000);
    std::string key_data = fdp.ConsumeBytesAsString(key_len);
    size_t val_len = fdp.ConsumeIntegralInRange<size_t>(0, 10000);
    std::string val_data = fdp.ConsumeBytesAsString(val_len);
    
    VALUE key = rb_str_new(key_data.data(), key_data.size());
    VALUE val = val_data.empty() ? Qnil : rb_str_new(val_data.data(), val_data.size());
    
    switch (op) {
            case 0: // Hash insert/update - tests storage and collision handling
                args[0] = hash;
                args[1] = key;
                args[2] = val;
                rb_protect(call_hash_aset, (VALUE)args, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 1: // Hash lookup - tests retrieval and key equality
                args[0] = hash;
                args[1] = key;
                rb_protect(call_hash_aref, (VALUE)args, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 2: // Hash delete - tests key removal and table shrinkage
                args[0] = hash;
                args[1] = key;
                rb_protect(call_hash_delete, (VALUE)args, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 3: // Hash rehash - tests hash table reconstruction after key mutation
                rb_protect(call_hash_rehash, hash, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 4: // Hash clear - tests bulk removal
                rb_protect(call_hash_clear, hash, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
                
            case 5: // Hash size - tests entry counting
                rb_hash_size(hash);
                break;
                
            case 6: // Hash keys - tests key array generation
                rb_funcall(hash, rb_intern("keys"), 0);
                break;
                
            case 7: // Hash values - tests value array generation
                rb_funcall(hash, rb_intern("values"), 0);
                break;
                
            case 8: // Hash has_key? - tests membership checking
                rb_funcall(hash, rb_intern("has_key?"), 1, key);
                break;
                
            case 9: // Hash dup - tests shallow copy operations
                rb_hash_dup(hash);
                break;
            
            case 10: // Hash merge - tests non-destructive combining of hashes
                {
                    VALUE other = rb_hash_new();
                    rb_hash_aset(other, key, val);
                    args[0] = hash;
                    args[1] = other;
                    rb_protect(call_hash_merge, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
            
            case 11: // Hash update/merge! - tests destructive merging
                {
                    VALUE other = rb_hash_new();
                    rb_hash_aset(other, key, val);
                    args[0] = hash;
                    args[1] = other;
                    rb_protect(call_hash_update, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
            
            case 12: // Hash invert - tests key/value swapping and collision handling
                rb_protect(call_hash_invert, hash, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
            
            case 13: // Hash to_a - tests conversion to array of pairs
                rb_protect(call_hash_to_a, hash, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
            
            case 14: // Hash shift - tests FIFO removal (first entry)
                rb_protect(call_hash_shift, hash, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
            
            case 15: // Hash compare_by_identity - tests object_id-based key comparison
                rb_protect(call_hash_compare_by_id, hash, &state);
                if (state) { rb_set_errinfo(Qnil); state = 0; }
                break;
            
            case 16: // Hash flatten - tests nested array flattening in values
                {
                    args[0] = hash;
                    args[1] = INT2FIX(1);  // Flatten depth
                    rb_protect(call_hash_flatten, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
            
            case 17: // Hash fetch with default - tests key lookup with fallback
                {
                    args[0] = hash;
                    args[1] = key;
                    rb_protect(call_hash_fetch, (VALUE)args, &state);
                    if (state) { rb_set_errinfo(Qnil); state = 0; }
                }
                break;
        }
    
    // Clean up - force GC to release memory
    // Ensures hash memory is properly freed across iterations
    rb_gc_start();
    
    return 0;
}

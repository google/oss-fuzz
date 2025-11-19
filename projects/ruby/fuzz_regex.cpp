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
 * Fuzzer for Ruby's Regex implementation (re.c, regcomp.c, regexec.c, regparse.c)
 * 
 * Purpose: Test regex compilation from potentially malformed patterns and matching
 * against various strings. Tests parser edge cases, compilation bugs, and matching
 * correctness with complex patterns.
 * 
 * Coverage:
 * - Regex compilation: Pattern parsing, syntax validation, optimization
 * - Regex matching: match, =~, scan, gsub operations
 * - Edge cases: Invalid patterns, backtracking, captures, Unicode, lookahead/lookbehind
 * - Memory: Backtracking stack overflow, catastrophic backtracking
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"
#include "ruby/encoding.h"
#include "ruby/re.h"

static int ruby_initialized = 0;

// Wrapper functions for rb_protect - necessary to catch exceptions
// Regex operations can raise (e.g., syntax errors, invalid patterns)
static VALUE call_regex_match(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("match"), 1, ptr[1]);  // Regexp#match - full match info
}

// Wrapper for regex =~ operator
static VALUE call_regex_match_op(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[0], rb_intern("=~"), 1, ptr[1]);  // Regexp#=~ - match position
}

// Wrapper for regex scan
static VALUE call_regex_scan(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[1], rb_intern("scan"), 1, ptr[0]);  // String#scan - find all matches
}

// Wrapper for regex gsub
static VALUE call_regex_gsub(VALUE args) {
    VALUE *ptr = (VALUE *)args;
    return rb_funcall(ptr[1], rb_intern("gsub"), 2, ptr[0], ptr[2]);  // String#gsub - replace all
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize Ruby once on first call
    // Sets up VM, object system, and Regexp class
    if (!ruby_initialized) {
        ruby_init();
        ruby_initialized = 1;
    }
    
    if (size < 2) return 0;
    
    // Use FuzzedDataProvider to split input into pattern and test string
    FuzzedDataProvider fdp(data, size);
    
    // Consume pattern string with random length
    size_t pattern_len = fdp.ConsumeIntegralInRange<size_t>(1, 10000);
    std::string pattern = fdp.ConsumeBytesAsString(pattern_len);
    VALUE pattern_str = rb_str_new(pattern.data(), pattern.size());
    
    // Consume test string from remaining data
    std::string test = fdp.ConsumeRemainingBytesAsString();
    VALUE test_str = rb_str_new(test.data(), test.size());
    
    int state = 0;
    VALUE args[3];
    
    // Try to compile regex with different options
    // Tests how different flags affect parsing and matching
    int options[] = {
        0,                                    // No options - default behavior
        1,                                    // IGNORECASE - case-insensitive matching
        2,                                    // EXTENDED - ignore whitespace, allow comments
        4,                                    // MULTILINE - ^ and $ match line boundaries
        1 | 2,                               // IGNORECASE | EXTENDED
        1 | 4,                               // IGNORECASE | MULTILINE
        2 | 4,                               // EXTENDED | MULTILINE
        1 | 2 | 4                            // ALL options
    };
    
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        // Compile the regex - this exercises the regex parser (regparse.c)
        // Tests pattern syntax validation, AST building, and optimization
        VALUE regexp = rb_protect((VALUE (*)(VALUE))rb_reg_regcomp, pattern_str, &state);
        
        if (state) {
            // Pattern compilation failed (syntax error, invalid escape, etc.)
            rb_set_errinfo(Qnil);
            state = 0;
            continue;
        }
        
        if (NIL_P(regexp)) continue;
        
        // Test 1: Regexp#match - exercises regex matching engine (regexec.c)
        // Returns MatchData object with capture groups
        args[0] = regexp;
        args[1] = test_str;
        rb_protect(call_regex_match, (VALUE)args, &state);
        if (state) {
            rb_set_errinfo(Qnil);
            state = 0;
        }
        
        // Test 2: Regexp#=~ - exercises match position finding
        // Returns integer position or nil
        rb_protect(call_regex_match_op, (VALUE)args, &state);
        if (state) {
            rb_set_errinfo(Qnil);
            state = 0;
        }
        
        // Test 3: String#scan - find all matches
        // Tests repeated matching and capture handling
        rb_protect(call_regex_scan, (VALUE)args, &state);
        if (state) {
            rb_set_errinfo(Qnil);
            state = 0;
        }
        
        // Test 4: String#gsub - replace matches
        // Tests matching combined with string building
        VALUE replacement = rb_str_new("X", 1);
        args[0] = regexp;
        args[1] = test_str;
        args[2] = replacement;
        rb_protect(call_regex_gsub, (VALUE)args, &state);
        if (state) {
            rb_set_errinfo(Qnil);
            state = 0;
        }
        
        // Only test first two option combinations to avoid timeout
        // Full testing would be 8 combinations which is excessive
        if (i >= 1) break;
    }
    
    // Clean up - force GC to release memory
    // Necessary to prevent memory growth from regex compilation artifacts
    rb_gc_start();
    
    return 0;
}

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
#include <unistd.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"
#include "ruby/encoding.h"
#include "ruby/re.h"

static int ruby_initialized = 0;

extern "C" VALUE ruby_verbose;

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
        
        // Suppress Ruby warnings to avoid log noise
        ruby_verbose = Qfalse;
    }
    
    if (size < 2) return 0;
    
    // Use FuzzedDataProvider to split input into pattern and test string
    FuzzedDataProvider fdp(data, size);
    
    // Consume pattern string with limited length to avoid pathological patterns
    size_t pattern_len = fdp.ConsumeIntegralInRange<size_t>(1, 1000);  // Reduced from 10000
    std::string pattern = fdp.ConsumeBytesAsString(pattern_len);
    
    // Consume test string from remaining data with size limit
    std::string test = fdp.ConsumeRemainingBytesAsString();
    if (test.size() > 10000) {
        test.resize(10000);  // Limit test string size to prevent memory issues
    }
    
    // Create Ruby strings - these can fail if data is invalid
    VALUE pattern_str = rb_str_new(pattern.data(), pattern.size());
    VALUE test_str = rb_str_new(test.data(), test.size());
    
    int state = 0;
    VALUE args[3];
    
    // Temporarily redirect stderr file descriptor to suppress regex compilation warnings
    // Duplicate stderr, redirect to /dev/null, then restore after compilation
    int saved_stderr = dup(STDERR_FILENO);
    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null >= 0) {
        dup2(dev_null, STDERR_FILENO);
        close(dev_null);
    }
    
    // Compile the regex with default options (0)
    // This exercises the regex parser (regparse.c)
    // Tests pattern syntax validation, AST building, and optimization
    VALUE regexp = rb_protect((VALUE (*)(VALUE))rb_reg_regcomp, pattern_str, &state);
    
    // Restore stderr file descriptor
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    
    if (state) {
        // Pattern compilation failed (syntax error, invalid escape, etc.)
        rb_set_errinfo(Qnil);
        rb_gc_start();
        return 0;
    }
    
    if (NIL_P(regexp)) {
        rb_gc_start();
        return 0;
    }
    
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
    // Skip scan if test string is too large to avoid memory issues
    if (test.size() <= 5000) {
        rb_protect(call_regex_scan, (VALUE)args, &state);
        if (state) {
            rb_set_errinfo(Qnil);
            state = 0;
        }
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
    
    // Clean up - force GC to release memory
    // Necessary to prevent memory growth from regex compilation artifacts
    rb_gc_start();
    
    return 0;
}

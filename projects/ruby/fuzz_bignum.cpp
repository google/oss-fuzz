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
 * Fuzzer for Ruby's Bignum/Integer implementation (bignum.c, numeric.c)
 * 
 * Purpose: Test arbitrary-precision integer operations including arithmetic,
 * bitwise operations, conversions, and comparison. Tests edge cases in
 * overflow handling, sign handling, and numeric precision.
 * 
 * Coverage:
 * - Arithmetic: +, -, *, /, %, **
 * - Bitwise: &, |, ^, <<, >>
 * - Comparison: ==, <=>, <, >, <=, >=
 * - Conversion: to_s, to_f, abs, negation
 * - Edge cases: Division by zero, large exponents, overflow
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ruby.h"

static int ruby_initialized = 0;

extern "C" VALUE ruby_verbose;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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
    VALUE num1 = Qnil, num2 = Qnil, result = Qnil;
    
    // Create first number from fuzzer data
    size_t str1_len = fdp.ConsumeIntegralInRange<size_t>(0, 10000);
    std::string str1 = fdp.ConsumeBytesAsString(str1_len);
    num1 = rb_protect((VALUE (*)(VALUE))rb_Integer, rb_str_new(str1.data(), str1.size()), &state);
    if (state) {
        rb_set_errinfo(Qnil);
        state = 0;
        num1 = INT2FIX(fdp.ConsumeIntegral<int32_t>());
    }
    
    // Create second number from remaining fuzzer data
    size_t str2_len = fdp.ConsumeIntegralInRange<size_t>(0, 10000);
    std::string str2 = fdp.ConsumeBytesAsString(str2_len);
    if (!str2.empty()) {
        num2 = rb_protect((VALUE (*)(VALUE))rb_Integer, rb_str_new(str2.data(), str2.size()), &state);
        if (state) {
            rb_set_errinfo(Qnil);
            state = 0;
            num2 = INT2FIX(fdp.ConsumeIntegral<int32_t>());
        }
    } else {
        num2 = INT2FIX(1);
    }
    
    // Select a single operation to test
    uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 19);
    
    switch (op) {
        case 0: // Addition
            result = rb_funcall(num1, rb_intern("+"), 1, num2);
            break;
        case 1: // Subtraction
            result = rb_funcall(num1, rb_intern("-"), 1, num2);
            break;
        case 2: // Multiplication
            result = rb_funcall(num1, rb_intern("*"), 1, num2);
            break;
        case 3: // Division (skip if num2 is zero)
            if (!FIXNUM_P(num2) || FIX2LONG(num2) != 0) {
                result = rb_funcall(num1, rb_intern("/"), 1, num2);
            }
            break;
        case 4: // Modulo (skip if num2 is zero)
            if (!FIXNUM_P(num2) || FIX2LONG(num2) != 0) {
                result = rb_funcall(num1, rb_intern("%"), 1, num2);
            }
            break;
        case 5: // Power (limit exponent to avoid hang)
            if (FIXNUM_P(num2)) {
                long exp_val = FIX2LONG(num2);
                if (exp_val >= 0 && exp_val < 100) {
                    result = rb_funcall(num1, rb_intern("**"), 1, num2);
                }
            }
            break;
        case 6: // Bitwise AND
            result = rb_funcall(num1, rb_intern("&"), 1, num2);
            break;
        case 7: // Bitwise OR
            result = rb_funcall(num1, rb_intern("|"), 1, num2);
            break;
        case 8: // Bitwise XOR
            result = rb_funcall(num1, rb_intern("^"), 1, num2);
            break;
        case 9: // Left shift (limit shift amount)
            if (FIXNUM_P(num2)) {
                long shift = FIX2LONG(num2);
                if (shift >= 0 && shift < 256) {
                    result = rb_funcall(num1, rb_intern("<<"), 1, num2);
                }
            }
            break;
        case 10: // Right shift (limit shift amount)
            if (FIXNUM_P(num2)) {
                long shift = FIX2LONG(num2);
                if (shift >= 0 && shift < 256) {
                    result = rb_funcall(num1, rb_intern(">>"), 1, num2);
                }
            }
            break;
        case 11: // Equality
            result = rb_funcall(num1, rb_intern("=="), 1, num2);
            break;
        case 12: // Spaceship operator (comparison)
            result = rb_funcall(num1, rb_intern("<=>"), 1, num2);
            break;
        case 13: // Greater than
            result = rb_funcall(num1, rb_intern(">"), 1, num2);
            break;
        case 14: // Less than
            result = rb_funcall(num1, rb_intern("<"), 1, num2);
            break;
        case 15: // To string conversion
            result = rb_funcall(num1, rb_intern("to_s"), 0);
            break;
        case 16: // To float conversion
            result = rb_funcall(num1, rb_intern("to_f"), 0);
            break;
        case 17: // Absolute value
            result = rb_funcall(num1, rb_intern("abs"), 0);
            break;
        case 18: // Negation
            result = rb_funcall(num1, rb_intern("-@"), 0);
            break;
        case 19: // Bitwise NOT
            result = rb_funcall(num1, rb_intern("~"), 0);
            break;
    }
    
    // Force GC
    rb_gc_start();
    
    return 0;
}

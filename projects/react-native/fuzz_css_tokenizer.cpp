/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Fuzz target: CSS tokenizer (CSSTokenizer)
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * SUITABILITY ASSESSMENT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The CSS tokenizer IS a worthwhile fuzz target because:
 *
 *   1. It is maintained entirely within React Native (not a vendored library),
 *      so bugs found are directly attributable to this project.
 *
 *   2. It lacks existing fuzz coverage: unlike fast_float (which has its own
 *      fuzz tests), the tokenizer state machine logic itself—including
 *      isIdentStart() with high-byte handling, wouldStartNumber() look-ahead,
 *      the consumeRunningValue() sliding-window logic, and hash/function
 *      token dispatch—has no fuzz test in the upstream test suite.
 *
 *   3. It is not a trivial wrapper: the tokenizer implements a subset of
 *      W3C CSS Syntax Level 3 (https://www.w3.org/TR/css-syntax-3/) covering
 *      tokenization §4.  The sliding-window state machine uses pointer
 *      arithmetic on string_view that has been a source of subtle bugs in
 *      similar implementations.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * ATTACK SURFACE & DATA FLOW
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The tokenizer is driven by any string-valued style prop that reaches the
 * Fabric renderer's C++ layer.  The concrete data flow is:
 *
 *   JavaScript / Server:
 *     <View style={{
 *       transform: [{rotate: "90deg"}],
 *       fontSize: "1.2rem",
 *       backgroundImage: "linear-gradient(to right, red, blue)",
 *     }} />
 *
 *   Bridge (JSI / MessageQueue):
 *     Prop values serialized as folly::dynamic strings passed from JS to C++
 *
 *   Fabric renderer (C++):
 *     StyleProps::apply() calls parseCSSProperty<T>(stringValue) which
 *     constructs CSSTokenizer(stringValue) and calls next() in a loop.
 *     ← THIS IS WHERE THE FUZZ TARGET RUNS
 *
 * In Server-Driven React Native (SDRN, used in production by Meta apps),
 * the string values originate from a server HTTP response, making them
 * directly attacker-controlled.  In bundled apps any compromised or
 * maliciously crafted JS bundle is the attack vector.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * BUG CLASSES TARGETED
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  A. consumeRunningValue() logic error:
 *     Uses position_ and remainingCharacters_ together as a sliding window.
 *     An off-by-one in advance() vs. consumeRunningValue() could produce a
 *     string_view pointing past the valid character range.
 *
 *  B. isIdentStart() / isIdent() high-byte handling:
 *     `static_cast<unsigned char>(c) > 0x80` is the check for high-byte
 *     code points indicating UTF-8 multi-byte sequences.  A signed char
 *     promotion or sign-extension bug here could misclassify bytes 0x80–0xFF
 *     and produce unbounded identifier consumption.
 *
 *  C. fast_float::from_chars_advanced interface:
 *     consumeNumber() passes raw pointers derived from string_view into
 *     fast_float.  Any mismatch between the tokenizer's position tracking
 *     and fast_float's returned pointer could corrupt position_.
 *
 *  D. Embedded NUL bytes:
 *     peek() returns '\0' on out-of-range access as the EndOfFile sentinel;
 *     an embedded NUL byte in the input causes premature termination of ident
 *     and number consumption before the actual string end.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * STRATEGY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Feed raw fuzz bytes as a std::string_view (CSS string) and drive the
 * tokenizer to EndOfFile.  A guard counter prevents timeouts on degenerate
 * inputs while still covering all token types the tokenizer can produce.
 * Every token field is consumed to prevent dead-code elimination.
 *
 * This target intentionally covers ONLY the tokenizer layer.  The full
 * parsing pipeline (CSSTokenizer → CSSSyntaxParser → CSSValueParser) is
 * exercised by the companion fuzz_css_value_parser target.
 */

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <react/renderer/css/CSSTokenizer.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // The tokenizer holds a string_view; the buffer is valid for this call.
  const std::string_view input(reinterpret_cast<const char *>(data), size);

  facebook::react::CSSTokenizer tokenizer(input);

  // next() advances at least one character per call, so size+2 is a safe
  // upper bound.  The +2 ensures we reach EndOfFile even on empty input.
  for (size_t guard = 0; guard < size + 2; ++guard) {
    const auto token = tokenizer.next();

    // Touch every accessor to prevent dead-code elimination and to ensure
    // string_view stability (no use-after-free from the sliding window).
    (void)token.type();
    (void)token.stringValue();   // string_view into original buffer
    (void)token.numericValue();  // float, produced by fast_float
    (void)token.unit();          // string_view for dimension suffix

    if (token.type() == facebook::react::CSSTokenType::EndOfFile) {
      break;
    }
  }

  return 0;
}


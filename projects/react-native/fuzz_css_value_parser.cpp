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
 * Fuzz target: CSS value parser (parseCSSProperty<>)
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * SUITABILITY ASSESSMENT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The CSS value parser IS an appropriate OSS-Fuzz target because:
 *
 *   1. The parsing pipeline spans three layers (CSSTokenizer → CSSSyntaxParser
 *      → CSSValueParser), each with independent state that can interact in
 *      non-obvious ways.  No existing fuzz test covers this pipeline end-to-
 *      end in the upstream React Native test suite.
 *
 *   2. The C++20 template dispatch inside CSSValueParser::consumeValue<> uses
 *      template specializations (CSSDataTypeParser<T>), concepts
 *      (CSSMaybeCompoundDataType), and if-constexpr chains.  Template-heavy
 *      code commonly has subtle runtime behavior that differs from compile-
 *      time evaluation; libFuzzer exercises runtime paths.
 *
 *   3. The pipeline is header-only but NOT trivially safe: CSSSyntaxParser
 *      maintains block/function nesting state; a parser that backtracks via
 *      `savedParser = *parser_` could mismatch state if the saved/restored
 *      objects share internal string_view pointers.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * ATTACK SURFACE & DATA FLOW
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * parseCSSProperty<T>(std::string_view) parses a SINGLE CSS property value.
 * It is called by the Fabric renderer for every string-valued style prop:
 *
 *   JavaScript (user-controlled or server-controlled):
 *     const style = {
 *       width: "50%",           // → parseCSSProperty<CSSLength, CSSPercentage>
 *       fontSize: "1.5rem",     // → parseCSSProperty<CSSLength>
 *       transform: "rotate(90deg)", // → parseCSSProperty<CSSAngle>
 *       aspectRatio: "16 / 9",  // → parseCSSProperty<CSSRatio>
 *       lineHeight: "1.4",      // → parseCSSProperty<CSSNumber>
 *     };
 *     <View style={style} />
 *
 *   Bridge (JSI):
 *     Prop strings transferred from JS runtime to C++ as std::string_view
 *
 *   Fabric renderer — StyleProps::apply() in C++:
 *     for each string prop:
 *       parseCSSProperty<AllowedTypes...>(propStringValue)
 *       ← OUR ENTRY POINT
 *
 * In Server-Driven React Native (SDRN), `style` objects come from a server
 * HTTP response, making the prop string values directly attacker-controlled
 * without requiring bundle compromise.  This is the most realistic
 * external-attacker scenario, present in production Facebook/Instagram builds.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * BUG CLASSES TARGETED
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  A. CSSSyntaxParser backtrack state corruption (UBSan / ASan):
 *     CSSValueParser saves and restores parser state via `savedParser = *parser_`
 *     when trying alternative type parsers.  If the saved CSSSyntaxParser
 *     contains string_view members that alias into the original input, an
 *     incorrect restore could leave dangling or inconsistent view state.
 *
 *  B. fast_float precision / pointer boundary (logic):
 *     Numbers like "1e+999999999" or "-0.0" expose edge cases in the
 *     float→string_view boundary computation inside consumeNumber().
 *
 *  C. CSS-wide keyword fallback interaction (logic):
 *     parseCSSProperty<T> always tries CSSWideKeyword first (initial,
 *     inherit, unset, revert-layer).  If the keyword parser partially
 *     consumes a token that should have matched a typed parser, the result
 *     is std::monostate returned for a valid input — a correctness bug
 *     rather than a crash, but still valuable to document.
 *
 *  D. Compound / ordered type dispatch (logic):
 *     CSSRatio requires exactly two numbers separated by '/'.  A crafted
 *     input that starts like a ratio but diverges mid-way exercises the
 *     backtrack path inside tryConsumeParser<CSSRatio>.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * STRATEGY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Call parseCSSProperty with different AllowedTypes combinations so that
 * libFuzzer discovers inputs exercising each typed code path independently
 * and in combination.  parseCSSProperty is stateless and returns
 * std::monostate on error; it never throws.
 *
 * All headers are constexpr / header-only; no library linking beyond the
 * fuzzing engine is required.  This target also subsumes the tokenizer
 * layer (CSSTokenizer) because every parseCSSProperty call drives the
 * tokenizer internally.  The companion fuzz_css_tokenizer target exercises
 * the tokenizer in isolation for better per-layer crash attribution.
 */

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <react/renderer/css/CSSValueParser.h>
#include <react/renderer/css/CSSAngle.h>
#include <react/renderer/css/CSSLength.h>
#include <react/renderer/css/CSSNumber.h>
#include <react/renderer/css/CSSPercentage.h>
#include <react/renderer/css/CSSRatio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const std::string_view input(reinterpret_cast<const char *>(data), size);

  // ── Single-type parsers ─────────────────────────────────────────────────
  // Each call exercises the full pipeline for one property value grammar.
  // "initial", "inherit", "unset", "revert-layer" are tried first by
  // parseCSSProperty regardless of AllowedTypes (CSSWideKeyword prefix).

  // <number>: "42", "3.14", "-0.5e2", "1e+38", "NaN", "Infinity"
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSNumber>(input);

  // <length>: "16px", "1.5rem", "100vw", "0.5em", "2.54cm"
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSLength>(input);

  // <percentage>: "50%", "100%", "0%", "33.33%"
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSPercentage>(input);

  // <angle>: "90deg", "1.5708rad", "0.25turn", "100grad"
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSAngle>(input);

  // <ratio>: "16 / 9", "4/3", "1.777/1"
  // Exercises the two-token ordered grammar with whitespace handling.
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSRatio>(input);

  // ── Compound / union parsers ────────────────────────────────────────────
  // Combining types exercises tryConsumeParser<> ordered dispatch:
  //   1. Try first type; backtrack via savedParser if no match.
  //   2. Try second type; backtrack again if no match.
  //   3. Return std::monostate.
  // The backtrack + restore path is the highest-risk code for state aliasing.

  // <length-percentage>: accepts a length or a percentage.
  // Used for width, height, padding, margin, top, left, …
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSLength,
      facebook::react::CSSPercentage>(input);

  // <number | length | percentage>: broadest numeric union.
  // Exercises three-way ordered dispatch.
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSNumber,
      facebook::react::CSSLength,
      facebook::react::CSSPercentage>(input);

  // <length | angle>: used for transform-related properties.
  // A number followed by an unrecognized unit (e.g. "10xyz") must parse
  // as neither, exercising the "no match after number scan" backtrack.
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSLength,
      facebook::react::CSSAngle>(input);

  // <number | ratio>: aspect-ratio coercion path.
  // A bare number like "1.5" is valid for aspect-ratio; "16/9" is also valid.
  (void)facebook::react::parseCSSProperty<
      facebook::react::CSSNumber,
      facebook::react::CSSRatio>(input);

  return 0;
}


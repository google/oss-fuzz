/* Copyright 2026 Google LLC
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
 * Fuzz zsh-style pattern matching (wildcard/glob patterns).
 *
 * Zsh has an extremely rich pattern matching system that goes far beyond
 * simple shell globs. It supports:
 *   - Extended globbing: (#i), (#b), (#a), (#s), (#e), (#q)
 *   - Alternation: (foo|bar)
 *   - Negation: (^foo), (~foo)
 *   - Ranges: [a-z], [^abc]
 *   - Recursive globbing
 *   - Quantifiers: (#cN,M)
 *   - Backreferences
 *
 * This is a standalone implementation of the core pattern matching
 * algorithm, independent of zsh internals.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATTERN_LEN 1024
#define MAX_DEPTH 64

/* Character class matching */
static int match_char_class(const char *cls, size_t cls_len, char c) {
  if (cls_len == 0)
    return 0;

  int negate = 0;
  size_t i = 0;

  if (cls[0] == '!' || cls[0] == '^') {
    negate = 1;
    i = 1;
  }

  int matched = 0;
  while (i < cls_len) {
    if (i + 2 < cls_len && cls[i + 1] == '-') {
      /* Range: a-z */
      if ((unsigned char)c >= (unsigned char)cls[i] &&
          (unsigned char)c <= (unsigned char)cls[i + 2]) {
        matched = 1;
      }
      i += 3;
    } else {
      if (c == cls[i])
        matched = 1;
      i++;
    }
  }

  return negate ? !matched : matched;
}

/* Recursive pattern matcher (simplified zsh-style) */
static int pattern_match(const char *pattern, size_t plen, const char *string,
                         size_t slen, int depth) {
  if (depth > MAX_DEPTH)
    return 0;

  size_t pi = 0, si = 0;

  while (pi < plen) {
    if (pattern[pi] == '*') {
      /* Skip consecutive stars */
      while (pi < plen && pattern[pi] == '*')
        pi++;

      if (pi >= plen)
        return 1; /* trailing * matches everything */

      /* Try matching rest of pattern at each position */
      for (size_t k = si; k <= slen; k++) {
        if (pattern_match(pattern + pi, plen - pi, string + k, slen - k,
                          depth + 1))
          return 1;
      }
      return 0;
    }

    if (si >= slen)
      return 0;

    if (pattern[pi] == '?') {
      /* Match any single character */
      pi++;
      si++;
    } else if (pattern[pi] == '[') {
      /* Character class */
      pi++;
      const char *cls_start = pattern + pi;
      size_t cls_len = 0;

      while (pi < plen && pattern[pi] != ']') {
        pi++;
        cls_len++;
      }

      if (pi < plen)
        pi++; /* skip ']' */

      if (!match_char_class(cls_start, cls_len, string[si]))
        return 0;
      si++;
    } else if (pattern[pi] == '(') {
      /* Group / alternation */
      pi++;
      int paren_depth = 1;
      const char *alt_start = pattern + pi;
      size_t alt_pos = 0;

      /* Try each alternative separated by '|' */
      while (pi < plen && paren_depth > 0) {
        if (pattern[pi] == '(')
          paren_depth++;
        else if (pattern[pi] == ')')
          paren_depth--;
        else if (pattern[pi] == '|' && paren_depth == 1) {
          /* Try this alternative */
          size_t alt_len = (pattern + pi) - alt_start;
          /* Try matching alternative + rest of pattern */
          for (size_t k = si; k <= slen; k++) {
            if (pattern_match(alt_start, alt_len, string + si, k - si,
                              depth + 1)) {
              size_t rest_pi = pi;
              /* Find closing paren */
              int d = 1;
              while (rest_pi < plen && d > 0) {
                rest_pi++;
                if (rest_pi < plen) {
                  if (pattern[rest_pi] == '(')
                    d++;
                  else if (pattern[rest_pi] == ')')
                    d--;
                }
              }
              if (rest_pi < plen)
                rest_pi++; /* skip ')' */

              if (pattern_match(pattern + rest_pi, plen - rest_pi, string + k,
                                slen - k, depth + 1))
                return 1;
            }
          }

          alt_start = pattern + pi + 1;
        }
        pi++;
      }

      /* Try last alternative */
      size_t alt_len = (pattern + pi - 1) - alt_start;
      if (alt_len > 0) {
        for (size_t k = si; k <= slen; k++) {
          if (pattern_match(alt_start, alt_len, string + si, k - si,
                            depth + 1)) {
            if (pattern_match(pattern + pi, plen - pi, string + k, slen - k,
                              depth + 1))
              return 1;
          }
        }
      }
      return 0;
    } else if (pattern[pi] == '\\' && pi + 1 < plen) {
      /* Escaped character */
      pi++;
      if (pattern[pi] != string[si])
        return 0;
      pi++;
      si++;
    } else {
      /* Literal character */
      if (pattern[pi] != string[si])
        return 0;
      pi++;
      si++;
    }
  }

  return si >= slen;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3 || size > 2048)
    return 0;

  /* Split input into pattern and string at the first null byte */
  const char *input = (const char *)data;
  size_t split = 0;
  for (size_t i = 0; i < size; i++) {
    if (input[i] == '\0') {
      split = i;
      break;
    }
  }

  if (split == 0 || split >= size - 1)
    return 0;

  const char *pattern = input;
  size_t plen = split;
  const char *string = input + split + 1;
  size_t slen = size - split - 1;

  /* Limit pattern length to prevent exponential blowup */
  if (plen > MAX_PATTERN_LEN || slen > MAX_PATTERN_LEN)
    return 0;

  pattern_match(pattern, plen, string, slen, 0);
  return 0;
}

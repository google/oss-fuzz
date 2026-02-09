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
 * Fuzz UTF-8 decoding and validation as performed by terminal emulators.
 *
 * Terminal emulators must properly handle:
 *   - Valid UTF-8 sequences (1-4 bytes)
 *   - Overlong encodings (must reject)
 *   - Surrogates (must reject)
 *   - Codepoints above U+10FFFF (must reject)
 *   - Truncated sequences
 *   - Invalid continuation bytes
 *   - Mixed ASCII and multibyte
 *   - Zero-width and combining characters
 *   - Right-to-left markers
 *
 * Bugs in UTF-8 decoders have led to security issues in terminals.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CODEPOINTS 4096
#define REPLACEMENT_CHAR 0xFFFD

typedef struct {
  uint32_t codepoint;
  int bytes;     /* Number of bytes consumed */
  int valid;     /* Whether the codepoint is valid */
  int width;     /* Display width: 0, 1, or 2 */
} DecodedChar;

/* Determine the display width of a Unicode codepoint */
static int codepoint_width(uint32_t cp) {
  /* C0/C1 control characters */
  if (cp < 0x20 || (cp >= 0x7F && cp < 0xA0))
    return 0;

  /* Zero-width characters */
  if (cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFEFF)
    return 0;

  /* Combining characters (simplified ranges) */
  if ((cp >= 0x0300 && cp <= 0x036F) || /* Combining Diacritical Marks */
      (cp >= 0x0483 && cp <= 0x0489) || /* Cyrillic combining */
      (cp >= 0x0591 && cp <= 0x05BD) || /* Hebrew combining */
      (cp >= 0x0610 && cp <= 0x061A) || /* Arabic combining */
      (cp >= 0x064B && cp <= 0x065F) || /* Arabic combining */
      (cp >= 0x0E31 && cp <= 0x0E3A) || /* Thai combining */
      (cp >= 0xFE20 && cp <= 0xFE2F))   /* Combining Half Marks */
    return 0;

  /* CJK and fullwidth characters */
  if ((cp >= 0x1100 && cp <= 0x115F) || /* Hangul Jamo */
      cp == 0x2329 || cp == 0x232A ||   /* Angle brackets */
      (cp >= 0x2E80 && cp <= 0x303E) || /* CJK Radicals */
      (cp >= 0x3041 && cp <= 0x33BF) || /* CJK/Katakana/Hiragana */
      (cp >= 0x3400 && cp <= 0x4DBF) || /* CJK Unified Ext A */
      (cp >= 0x4E00 && cp <= 0x9FFF) || /* CJK Unified */
      (cp >= 0xAC00 && cp <= 0xD7AF) || /* Hangul Syllables */
      (cp >= 0xF900 && cp <= 0xFAFF) || /* CJK Compatibility */
      (cp >= 0xFE10 && cp <= 0xFE19) || /* Vertical forms */
      (cp >= 0xFE30 && cp <= 0xFE6F) || /* CJK Compatibility Forms */
      (cp >= 0xFF01 && cp <= 0xFF60) || /* Fullwidth forms */
      (cp >= 0xFFE0 && cp <= 0xFFE6) || /* Fullwidth signs */
      (cp >= 0x20000 && cp <= 0x2FFFF)) /* CJK Unified Ext B+ */
    return 2;

  return 1;
}

/* Decode a single UTF-8 character from a byte stream */
static DecodedChar decode_utf8(const uint8_t *data, size_t len) {
  DecodedChar result;
  memset(&result, 0, sizeof(result));

  if (len == 0) {
    result.valid = 0;
    return result;
  }

  uint8_t b0 = data[0];

  if (b0 < 0x80) {
    /* ASCII */
    result.codepoint = b0;
    result.bytes = 1;
    result.valid = 1;
  } else if ((b0 & 0xE0) == 0xC0) {
    /* 2-byte sequence */
    if (len < 2 || (data[1] & 0xC0) != 0x80) {
      result.codepoint = REPLACEMENT_CHAR;
      result.bytes = 1;
      result.valid = 0;
    } else {
      result.codepoint = ((uint32_t)(b0 & 0x1F) << 6) | (data[1] & 0x3F);
      result.bytes = 2;
      /* Check for overlong encoding */
      result.valid = (result.codepoint >= 0x80);
      if (!result.valid)
        result.codepoint = REPLACEMENT_CHAR;
    }
  } else if ((b0 & 0xF0) == 0xE0) {
    /* 3-byte sequence */
    if (len < 3 || (data[1] & 0xC0) != 0x80 || (data[2] & 0xC0) != 0x80) {
      result.codepoint = REPLACEMENT_CHAR;
      result.bytes = 1;
      result.valid = 0;
    } else {
      result.codepoint = ((uint32_t)(b0 & 0x0F) << 12) |
                          ((uint32_t)(data[1] & 0x3F) << 6) |
                          (data[2] & 0x3F);
      result.bytes = 3;
      /* Check overlong and surrogates */
      result.valid = (result.codepoint >= 0x800) &&
                     !(result.codepoint >= 0xD800 && result.codepoint <= 0xDFFF);
      if (!result.valid)
        result.codepoint = REPLACEMENT_CHAR;
    }
  } else if ((b0 & 0xF8) == 0xF0) {
    /* 4-byte sequence */
    if (len < 4 || (data[1] & 0xC0) != 0x80 || (data[2] & 0xC0) != 0x80 ||
        (data[3] & 0xC0) != 0x80) {
      result.codepoint = REPLACEMENT_CHAR;
      result.bytes = 1;
      result.valid = 0;
    } else {
      result.codepoint = ((uint32_t)(b0 & 0x07) << 18) |
                          ((uint32_t)(data[1] & 0x3F) << 12) |
                          ((uint32_t)(data[2] & 0x3F) << 6) |
                          (data[3] & 0x3F);
      result.bytes = 4;
      /* Check overlong and max codepoint */
      result.valid = (result.codepoint >= 0x10000) &&
                     (result.codepoint <= 0x10FFFF);
      if (!result.valid)
        result.codepoint = REPLACEMENT_CHAR;
    }
  } else {
    /* Invalid lead byte (0x80-0xBF, 0xF8-0xFF) */
    result.codepoint = REPLACEMENT_CHAR;
    result.bytes = 1;
    result.valid = 0;
  }

  result.width = codepoint_width(result.codepoint);
  return result;
}

/* Process a buffer of UTF-8 encoded text as a terminal would */
static void process_utf8_stream(const uint8_t *data, size_t len) {
  DecodedChar decoded[MAX_CODEPOINTS];
  int num_decoded = 0;
  int total_width = 0;

  size_t i = 0;
  while (i < len && num_decoded < MAX_CODEPOINTS) {
    DecodedChar dc = decode_utf8(data + i, len - i);
    decoded[num_decoded++] = dc;
    total_width += dc.width;

    if (dc.bytes > 0)
      i += dc.bytes;
    else
      i++; /* avoid infinite loop */
  }

  /* Simulate line-breaking at a terminal width of 80 */
  int col = 0;
  for (int j = 0; j < num_decoded; j++) {
    int w = decoded[j].width;
    if (col + w > 80) {
      col = 0; /* wrap */
    }
    col += w;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 16384)
    return 0;

  process_utf8_stream(data, size);
  return 0;
}

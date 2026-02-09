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
 * Fuzz nmap's target specification parsing.
 *
 * Nmap supports complex target specifications: CIDR ranges (192.168.1.0/24),
 * octet ranges (10.0-5.1-255.1), hostname targets, IPv6 addresses, and
 * comma-separated lists. The parsing logic is a rich attack surface.
 *
 * This is a standalone fuzzer that re-implements the core target string
 * tokenization without pulling in nmap's full infrastructure.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>

/* Standalone target-spec tokenizer mimicking nmap's TargetGroup parsing */

struct TargetToken {
  enum Type {
    TOK_IPV4_ADDR,
    TOK_IPV4_CIDR,
    TOK_IPV4_RANGE,
    TOK_IPV6_ADDR,
    TOK_HOSTNAME,
    TOK_COMMA,
    TOK_DASH,
    TOK_SLASH,
    TOK_DOT,
    TOK_COLON,
    TOK_NUMBER,
    TOK_UNKNOWN,
    TOK_END
  };

  Type type;
  int value;
};

/* Parse an octet-range spec like "1-255" or "192" */
static int parse_octet_range(const char *s, size_t len) {
  if (len == 0 || len > 11)
    return -1;

  char buf[12];
  memcpy(buf, s, len);
  buf[len] = '\0';

  /* Check for range: e.g. "1-100" */
  char *dash = strchr(buf, '-');
  if (dash) {
    *dash = '\0';
    long lo = strtol(buf, NULL, 10);
    long hi = strtol(dash + 1, NULL, 10);
    if (lo < 0 || lo > 255 || hi < 0 || hi > 255)
      return -1;
    if (lo > hi)
      return -1;
    return (int)(hi - lo + 1);
  }

  /* Check for comma-separated: e.g. "1,2,3" */
  int count = 0;
  char *tok = strtok(buf, ",");
  while (tok) {
    long v = strtol(tok, NULL, 10);
    if (v < 0 || v > 255)
      return -1;
    count++;
    tok = strtok(NULL, ",");
  }
  return count > 0 ? count : -1;
}

/* Tokenize a CIDR notation: "192.168.1.0/24" */
static int parse_cidr(const char *s, size_t len) {
  if (len == 0 || len > 43)
    return -1;

  char buf[44];
  memcpy(buf, s, len);
  buf[len] = '\0';

  char *slash = strchr(buf, '/');
  if (!slash)
    return -1;

  *slash = '\0';
  long prefix = strtol(slash + 1, NULL, 10);

  /* Check if it looks like IPv6 */
  if (strchr(buf, ':')) {
    if (prefix < 0 || prefix > 128)
      return -1;
  } else {
    if (prefix < 0 || prefix > 32)
      return -1;
  }

  /* Count dots for IPv4 validation */
  int dots = 0;
  for (char *p = buf; *p; p++) {
    if (*p == '.')
      dots++;
  }

  if (!strchr(buf, ':') && dots != 3)
    return -1;

  return (int)prefix;
}

/* Parse a full target specification string */
static int parse_target_spec(const char *spec, size_t len) {
  if (len == 0)
    return 0;

  /* Split by whitespace and commas for multiple targets */
  char *buf = (char *)malloc(len + 1);
  if (!buf)
    return -1;
  memcpy(buf, spec, len);
  buf[len] = '\0';

  int targets_parsed = 0;
  char *saveptr = NULL;
  char *target = strtok_r(buf, " \t\n\r", &saveptr);

  while (target) {
    size_t tlen = strlen(target);

    if (strchr(target, '/')) {
      /* CIDR notation */
      parse_cidr(target, tlen);
    } else if (strchr(target, ':')) {
      /* Possibly IPv6 */
      /* Just validate length */
      if (tlen > 45) {
        free(buf);
        return -1;
      }
    } else {
      /* IPv4 or hostname */
      /* Try to parse as dotted-quad with ranges */
      int dots = 0;
      for (size_t i = 0; i < tlen; i++) {
        if (target[i] == '.')
          dots++;
      }

      if (dots == 3) {
        /* Parse each octet */
        char *octet_save = NULL;
        char *octet = strtok_r(target, ".", &octet_save);
        int octet_count = 0;
        while (octet && octet_count < 4) {
          parse_octet_range(octet, strlen(octet));
          octet_count++;
          octet = strtok_r(NULL, ".", &octet_save);
        }
      }
    }

    targets_parsed++;
    target = strtok_r(NULL, " \t\n\r", &saveptr);
  }

  free(buf);
  return targets_parsed;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 4096)
    return 0;

  /* Ensure null-terminated */
  char *str = (char *)malloc(size + 1);
  if (!str)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  parse_target_spec(str, size);

  free(str);
  return 0;
}

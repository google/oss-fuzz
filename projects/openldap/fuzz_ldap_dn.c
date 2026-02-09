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
 * Fuzz LDAP Distinguished Name (DN) parsing.
 *
 * LDAP DNs follow RFC 4514 format:
 *   CN=John Doe,OU=Users,DC=example,DC=com
 *
 * The parser handles:
 *   - Attribute type + value pairs separated by commas
 *   - Multi-valued RDNs separated by '+'
 *   - Escaped special characters (\, ", +, <, >, ;, =, #)
 *   - Hex-encoded values (#hexstring)
 *   - Quoted values ("value with spaces")
 *   - OID attribute types (1.2.3.4=value)
 *
 * This is a standalone parser that doesn't depend on libldap.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_RDN_COMPONENTS 64
#define MAX_AVA_LEN 512

typedef struct {
  char type[MAX_AVA_LEN];
  char value[MAX_AVA_LEN];
  int hex_encoded;
} AVA;

typedef struct {
  AVA components[4]; /* Multi-valued RDN */
  int num_components;
} RDN;

typedef struct {
  RDN rdns[MAX_RDN_COMPONENTS];
  int num_rdns;
} DN;

/* Check if a character is a DN special character */
static int is_special(char c) {
  return c == ',' || c == '+' || c == '"' || c == '\\' || c == '<' ||
         c == '>' || c == ';' || c == '=' || c == '#';
}

/* Parse a hex-encoded value (#hexstring) */
static int parse_hex_value(const char *s, size_t len, char *out,
                           size_t out_max) {
  if (len < 1 || s[0] != '#')
    return -1;

  size_t out_pos = 0;
  size_t i = 1;

  while (i + 1 < len && out_pos < out_max - 1) {
    char hi = s[i];
    char lo = s[i + 1];

    int h = -1, l = -1;
    if (hi >= '0' && hi <= '9')
      h = hi - '0';
    else if (hi >= 'a' && hi <= 'f')
      h = hi - 'a' + 10;
    else if (hi >= 'A' && hi <= 'F')
      h = hi - 'A' + 10;

    if (lo >= '0' && lo <= '9')
      l = lo - '0';
    else if (lo >= 'a' && lo <= 'f')
      l = lo - 'a' + 10;
    else if (lo >= 'A' && lo <= 'F')
      l = lo - 'A' + 10;

    if (h < 0 || l < 0)
      return -1;

    out[out_pos++] = (char)((h << 4) | l);
    i += 2;
  }

  out[out_pos] = '\0';
  return (int)out_pos;
}

/* Parse a quoted string value */
static int parse_quoted_value(const char *s, size_t len, char *out,
                              size_t out_max) {
  if (len < 2 || s[0] != '"')
    return -1;

  size_t out_pos = 0;
  size_t i = 1;

  while (i < len && s[i] != '"' && out_pos < out_max - 1) {
    if (s[i] == '\\' && i + 1 < len) {
      i++;
      /* Handle hex escape \XX */
      if (i + 1 < len) {
        int h = -1, l = -1;
        if (s[i] >= '0' && s[i] <= '9')
          h = s[i] - '0';
        else if (s[i] >= 'a' && s[i] <= 'f')
          h = s[i] - 'a' + 10;
        else if (s[i] >= 'A' && s[i] <= 'F')
          h = s[i] - 'A' + 10;

        if (s[i + 1] >= '0' && s[i + 1] <= '9')
          l = s[i + 1] - '0';
        else if (s[i + 1] >= 'a' && s[i + 1] <= 'f')
          l = s[i + 1] - 'a' + 10;
        else if (s[i + 1] >= 'A' && s[i + 1] <= 'F')
          l = s[i + 1] - 'A' + 10;

        if (h >= 0 && l >= 0) {
          out[out_pos++] = (char)((h << 4) | l);
          i += 2;
          continue;
        }
      }
      out[out_pos++] = s[i];
      i++;
    } else {
      out[out_pos++] = s[i];
      i++;
    }
  }

  out[out_pos] = '\0';
  return (int)out_pos;
}

/* Parse a single attribute type (e.g., "CN", "OU", "1.2.3.4") */
static int parse_attr_type(const char *s, size_t len, char *out,
                           size_t out_max) {
  size_t i = 0;
  size_t out_pos = 0;

  /* Skip leading whitespace */
  while (i < len && (s[i] == ' ' || s[i] == '\t'))
    i++;

  /* Read attribute type: alpha + (alpha | digit | '-')* or OID */
  while (i < len && out_pos < out_max - 1) {
    char c = s[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.') {
      out[out_pos++] = c;
      i++;
    } else {
      break;
    }
  }

  out[out_pos] = '\0';
  return (int)i;
}

/* Parse a full DN string */
static int parse_dn(const char *s, size_t len, DN *dn) {
  dn->num_rdns = 0;

  if (len == 0)
    return 0;

  size_t i = 0;

  while (i < len && dn->num_rdns < MAX_RDN_COMPONENTS) {
    RDN *rdn = &dn->rdns[dn->num_rdns];
    rdn->num_components = 0;

    do {
      if (rdn->num_components >= 4)
        break;

      AVA *ava = &rdn->components[rdn->num_components];
      memset(ava, 0, sizeof(*ava));

      /* Skip whitespace */
      while (i < len && (s[i] == ' ' || s[i] == '\t'))
        i++;

      /* Parse attribute type */
      int consumed = parse_attr_type(s + i, len - i, ava->type, MAX_AVA_LEN);
      i += consumed;

      /* Skip whitespace around '=' */
      while (i < len && s[i] == ' ')
        i++;
      if (i < len && s[i] == '=')
        i++;
      while (i < len && s[i] == ' ')
        i++;

      /* Parse attribute value */
      if (i < len && s[i] == '#') {
        /* Hex-encoded value */
        size_t val_start = i;
        i++; /* skip '#' */
        while (i < len && ((s[i] >= '0' && s[i] <= '9') ||
                           (s[i] >= 'a' && s[i] <= 'f') ||
                           (s[i] >= 'A' && s[i] <= 'F')))
          i++;
        parse_hex_value(s + val_start, i - val_start, ava->value, MAX_AVA_LEN);
        ava->hex_encoded = 1;
      } else if (i < len && s[i] == '"') {
        /* Quoted value */
        size_t val_start = i;
        i++; /* skip opening quote */
        while (i < len && s[i] != '"') {
          if (s[i] == '\\' && i + 1 < len)
            i++;
          i++;
        }
        if (i < len)
          i++; /* skip closing quote */
        parse_quoted_value(s + val_start, i - val_start, ava->value,
                           MAX_AVA_LEN);
      } else {
        /* Unquoted value */
        size_t val_pos = 0;
        while (i < len && s[i] != ',' && s[i] != '+' && s[i] != ';' &&
               val_pos < MAX_AVA_LEN - 1) {
          if (s[i] == '\\' && i + 1 < len) {
            i++;
            ava->value[val_pos++] = s[i];
          } else {
            ava->value[val_pos++] = s[i];
          }
          i++;
        }
        ava->value[val_pos] = '\0';
        /* Trim trailing whitespace */
        while (val_pos > 0 && ava->value[val_pos - 1] == ' ')
          ava->value[--val_pos] = '\0';
      }

      rdn->num_components++;

      /* Check for multi-valued RDN ('+') */
    } while (i < len && s[i] == '+' && ++i);

    dn->num_rdns++;

    /* Skip RDN separator (',' or ';') */
    if (i < len && (s[i] == ',' || s[i] == ';'))
      i++;
    else
      break;
  }

  return dn->num_rdns;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 4096)
    return 0;

  char *str = (char *)malloc(size + 1);
  if (!str)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  DN dn;
  parse_dn(str, size, &dn);

  free(str);
  return 0;
}

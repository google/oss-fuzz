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
 * Fuzz LDAP search filter parsing (RFC 4515).
 *
 * LDAP search filters follow a parenthesized prefix notation:
 *   (&(objectClass=person)(cn=John*))
 *   (|(uid=admin)(uid=root))
 *   (!(cn=test))
 *   (&(age>=18)(age<=65))
 *   (cn=*substring*)
 *   (objectClass=*)
 *   (userCertificate;binary=\04\03\02\01)
 *
 * Filter types: =, ~=, >=, <=, :=, =*substr*, =*
 * Combinators: & (AND), | (OR), ! (NOT)
 *
 * This is a standalone recursive-descent parser for LDAP filters.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_FILTER_DEPTH 32
#define MAX_ATTR_LEN 256

typedef enum {
  FILTER_AND,
  FILTER_OR,
  FILTER_NOT,
  FILTER_EQUAL,
  FILTER_APPROX,
  FILTER_GE,
  FILTER_LE,
  FILTER_PRESENT,
  FILTER_SUBSTRING,
  FILTER_EXTENSIBLE,
  FILTER_INVALID
} FilterType;

typedef struct Filter {
  FilterType type;
  char attr[MAX_ATTR_LEN];
  char value[MAX_ATTR_LEN];
  struct Filter *children[16]; /* for AND/OR/NOT */
  int num_children;
  /* Substring parts */
  char sub_initial[MAX_ATTR_LEN];
  char sub_any[MAX_ATTR_LEN];
  char sub_final[MAX_ATTR_LEN];
} Filter;

static Filter *parse_filter(const char *s, size_t len, size_t *consumed,
                             int depth);

static void free_filter(Filter *f) {
  if (!f)
    return;
  for (int i = 0; i < f->num_children; i++)
    free_filter(f->children[i]);
  free(f);
}

/* Parse the attribute description part */
static size_t parse_attr_desc(const char *s, size_t len, char *out,
                              size_t out_max) {
  size_t i = 0;
  size_t pos = 0;

  while (i < len && pos < out_max - 1) {
    char c = s[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '.' || c == ';') {
      out[pos++] = c;
      i++;
    } else {
      break;
    }
  }

  out[pos] = '\0';
  return i;
}

/* Parse an assertion value with escape handling */
static size_t parse_value(const char *s, size_t len, char *out,
                          size_t out_max) {
  size_t i = 0;
  size_t pos = 0;

  while (i < len && s[i] != ')' && pos < out_max - 1) {
    if (s[i] == '\\' && i + 2 < len) {
      /* Hex escape \XX */
      int h = -1, l = -1;
      if (s[i + 1] >= '0' && s[i + 1] <= '9')
        h = s[i + 1] - '0';
      else if (s[i + 1] >= 'a' && s[i + 1] <= 'f')
        h = s[i + 1] - 'a' + 10;
      else if (s[i + 1] >= 'A' && s[i + 1] <= 'F')
        h = s[i + 1] - 'A' + 10;

      if (s[i + 2] >= '0' && s[i + 2] <= '9')
        l = s[i + 2] - '0';
      else if (s[i + 2] >= 'a' && s[i + 2] <= 'f')
        l = s[i + 2] - 'a' + 10;
      else if (s[i + 2] >= 'A' && s[i + 2] <= 'F')
        l = s[i + 2] - 'A' + 10;

      if (h >= 0 && l >= 0) {
        out[pos++] = (char)((h << 4) | l);
        i += 3;
        continue;
      }
    }
    out[pos++] = s[i++];
  }

  out[pos] = '\0';
  return i;
}

/* Parse a simple filter: (attr=value), (attr>=value), etc. */
static Filter *parse_simple_filter(const char *s, size_t len,
                                   size_t *consumed) {
  Filter *f = (Filter *)calloc(1, sizeof(Filter));
  if (!f)
    return NULL;

  size_t i = 0;

  /* Parse attribute */
  i += parse_attr_desc(s + i, len - i, f->attr, MAX_ATTR_LEN);

  if (i >= len) {
    free(f);
    *consumed = i;
    return NULL;
  }

  /* Determine filter type */
  if (s[i] == '=' ) {
    i++;
    if (i < len && s[i] == '*' &&
        (i + 1 >= len || s[i + 1] == ')')) {
      /* Presence filter: (attr=*) */
      f->type = FILTER_PRESENT;
      i++;
    } else if (i < len && strchr(s + i, '*')) {
      /* Substring filter: (attr=*sub*) */
      f->type = FILTER_SUBSTRING;
      i += parse_value(s + i, len - i, f->value, MAX_ATTR_LEN);

      /* Split value into initial, any, final at '*' characters */
      char *star = strchr(f->value, '*');
      if (star) {
        size_t init_len = star - f->value;
        if (init_len > 0 && init_len < MAX_ATTR_LEN)
          memcpy(f->sub_initial, f->value, init_len);

        char *last_star = strrchr(f->value, '*');
        if (last_star && last_star[1])
          strncpy(f->sub_final, last_star + 1, MAX_ATTR_LEN - 1);
      }
    } else {
      /* Equality filter: (attr=value) */
      f->type = FILTER_EQUAL;
      i += parse_value(s + i, len - i, f->value, MAX_ATTR_LEN);
    }
  } else if (i + 1 < len && s[i] == '~' && s[i + 1] == '=') {
    f->type = FILTER_APPROX;
    i += 2;
    i += parse_value(s + i, len - i, f->value, MAX_ATTR_LEN);
  } else if (i + 1 < len && s[i] == '>' && s[i + 1] == '=') {
    f->type = FILTER_GE;
    i += 2;
    i += parse_value(s + i, len - i, f->value, MAX_ATTR_LEN);
  } else if (i + 1 < len && s[i] == '<' && s[i + 1] == '=') {
    f->type = FILTER_LE;
    i += 2;
    i += parse_value(s + i, len - i, f->value, MAX_ATTR_LEN);
  } else if (i + 1 < len && s[i] == ':' && s[i + 1] == '=') {
    f->type = FILTER_EXTENSIBLE;
    i += 2;
    i += parse_value(s + i, len - i, f->value, MAX_ATTR_LEN);
  } else {
    f->type = FILTER_INVALID;
  }

  *consumed = i;
  return f;
}

/* Parse a compound or simple filter */
static Filter *parse_filter(const char *s, size_t len, size_t *consumed,
                             int depth) {
  if (depth > MAX_FILTER_DEPTH || len < 2) {
    *consumed = len;
    return NULL;
  }

  size_t i = 0;

  /* Skip whitespace */
  while (i < len && (s[i] == ' ' || s[i] == '\t'))
    i++;

  /* Must start with '(' */
  if (i >= len || s[i] != '(') {
    *consumed = i;
    return NULL;
  }
  i++; /* skip '(' */

  Filter *f = NULL;

  if (i < len && (s[i] == '&' || s[i] == '|')) {
    /* AND or OR filter */
    f = (Filter *)calloc(1, sizeof(Filter));
    if (!f) {
      *consumed = i;
      return NULL;
    }
    f->type = (s[i] == '&') ? FILTER_AND : FILTER_OR;
    i++;

    /* Parse child filters */
    while (i < len && s[i] != ')' && f->num_children < 16) {
      size_t child_consumed = 0;
      Filter *child = parse_filter(s + i, len - i, &child_consumed, depth + 1);
      if (child)
        f->children[f->num_children++] = child;
      i += child_consumed;
      if (child_consumed == 0)
        break;
    }
  } else if (i < len && s[i] == '!') {
    /* NOT filter */
    f = (Filter *)calloc(1, sizeof(Filter));
    if (!f) {
      *consumed = i;
      return NULL;
    }
    f->type = FILTER_NOT;
    i++;

    size_t child_consumed = 0;
    Filter *child = parse_filter(s + i, len - i, &child_consumed, depth + 1);
    if (child)
      f->children[f->num_children++] = child;
    i += child_consumed;
  } else {
    /* Simple filter */
    size_t simple_consumed = 0;
    f = parse_simple_filter(s + i, len - i, &simple_consumed);
    i += simple_consumed;
  }

  /* Find closing ')' */
  while (i < len && s[i] != ')')
    i++;
  if (i < len)
    i++; /* skip ')' */

  *consumed = i;
  return f;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3 || size > 8192)
    return 0;

  char *str = (char *)malloc(size + 1);
  if (!str)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  size_t consumed = 0;
  Filter *f = parse_filter(str, size, &consumed, 0);
  free_filter(f);

  free(str);
  return 0;
}

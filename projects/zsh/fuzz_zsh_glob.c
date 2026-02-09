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
 * Fuzz zsh glob pattern parsing and qualifier extraction.
 *
 * Zsh glob qualifiers are specified in parentheses at the end of a
 * glob pattern:  ls *(om[1,5])  or  echo **\/*.c(.)
 *
 * Qualifiers can specify file type, permissions, ownership, time,
 * size, and more:
 *   (.)  - regular files only
 *   (/)  - directories only
 *   (@)  - symlinks only
 *   (*)  - executable files
 *   (r)  - readable
 *   (w)  - writable
 *   (x)  - executable
 *   (R)  - world-readable
 *   (om) - sort by modification time
 *   (On) - reverse sort by name
 *   ([1,5]) - select range
 *   (L+10) - size > 10 bytes
 *   (mh-1) - modified in last hour
 *
 * This fuzzer parses glob qualifier strings without depending on zsh.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_QUALIFIERS 32

typedef struct {
  int type; /* '.', '/', '@', '=', 'p', '*', '%' */
  int perm; /* r, w, x, R, W, X, s, S, t */
  int sort_type; /* 'n', 'L', 'l', 'a', 'm', 'c', 'd', 'N' */
  int sort_reverse;
  long size_value;
  char size_qualifier; /* +, -, nothing */
  char size_unit; /* 'k', 'M', 'G', 'T', 'P' */
  int time_type; /* 'a', 'm', 'c' */
  char time_unit; /* 's', 'm', 'h', 'd', 'w', 'M' */
  long time_value;
  int range_start;
  int range_end;
  int negate;
} GlobQualifier;

/* Parse a glob qualifier string like "(om[1,5].)" */
static int parse_qualifiers(const char *s, size_t len, GlobQualifier *quals,
                            int max_quals) {
  if (len < 2 || s[0] != '(')
    return -1;

  int nqual = 0;
  size_t i = 1;

  while (i < len && s[i] != ')' && nqual < max_quals) {
    GlobQualifier q = {0};
    q.range_start = -1;
    q.range_end = -1;

    /* Handle negation */
    if (s[i] == '^') {
      q.negate = 1;
      i++;
      if (i >= len)
        break;
    }

    switch (s[i]) {
    case '.': /* regular file */
    case '/': /* directory */
    case '@': /* symlink */
    case '=': /* socket */
    case 'p': /* named pipe */
    case '*': /* executable */
    case '%': /* device file */
      q.type = s[i];
      i++;
      break;

    case 'r':
    case 'w':
    case 'x':
    case 'R':
    case 'W':
    case 'X':
    case 's':
    case 'S':
    case 't':
      q.perm = s[i];
      i++;
      break;

    case 'o': /* sort order */
    case 'O': /* reverse sort */
      q.sort_reverse = (s[i] == 'O');
      i++;
      if (i < len) {
        q.sort_type = s[i];
        i++;
      }
      break;

    case 'L': /* file size */
      i++;
      if (i < len && (s[i] == '+' || s[i] == '-')) {
        q.size_qualifier = s[i];
        i++;
      }
      /* Parse size value */
      q.size_value = 0;
      while (i < len && s[i] >= '0' && s[i] <= '9') {
        q.size_value = q.size_value * 10 + (s[i] - '0');
        i++;
      }
      /* Parse unit */
      if (i < len && (s[i] == 'k' || s[i] == 'M' || s[i] == 'G' ||
                       s[i] == 'T' || s[i] == 'P')) {
        q.size_unit = s[i];
        i++;
      }
      break;

    case 'm': /* modification time */
    case 'a': /* access time */
    case 'c': /* change time */
      q.time_type = s[i];
      i++;
      /* Parse time unit */
      if (i < len && (s[i] == 's' || s[i] == 'm' || s[i] == 'h' ||
                       s[i] == 'd' || s[i] == 'w' || s[i] == 'M')) {
        q.time_unit = s[i];
        i++;
      }
      /* Parse +/- and value */
      if (i < len && (s[i] == '+' || s[i] == '-')) {
        q.size_qualifier = s[i]; /* reuse */
        i++;
      }
      q.time_value = 0;
      while (i < len && s[i] >= '0' && s[i] <= '9') {
        q.time_value = q.time_value * 10 + (s[i] - '0');
        i++;
      }
      break;

    case '[': /* range selector */
      i++;
      q.range_start = 0;
      while (i < len && s[i] >= '0' && s[i] <= '9') {
        q.range_start = q.range_start * 10 + (s[i] - '0');
        i++;
      }
      if (i < len && s[i] == ',') {
        i++;
        q.range_end = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
          q.range_end = q.range_end * 10 + (s[i] - '0');
          i++;
        }
      }
      if (i < len && s[i] == ']')
        i++;
      break;

    case 'u': /* owner */
    case 'g': /* group */
      i++;
      /* Skip numeric or named owner/group */
      if (i < len && s[i] >= '0' && s[i] <= '9') {
        while (i < len && s[i] >= '0' && s[i] <= '9')
          i++;
      } else if (i < len && s[i] == ':') {
        i++;
        while (i < len && s[i] != ':' && s[i] != ')' && s[i] != ' ')
          i++;
        if (i < len && s[i] == ':')
          i++;
      }
      break;

    case 'f': /* file mode */
      i++;
      /* Parse mode specification */
      while (i < len && s[i] != ')' && s[i] != ' ' &&
             !(s[i] >= 'a' && s[i] <= 'z' && s[i] != 'r' && s[i] != 'w' &&
               s[i] != 'x'))
        i++;
      break;

    case 'e': /* execute code */
    case '+': /* execute function */
      i++;
      /* Skip to matching delimiter */
      if (i < len) {
        char delim = s[i];
        i++;
        while (i < len && s[i] != delim)
          i++;
        if (i < len)
          i++;
      }
      break;

    case 'N': /* null glob */
    case 'D': /* include dots */
    case 'n': /* numeric sort */
    case 'Y': /* short circuit */
      i++;
      /* Y takes a number */
      if (s[i - 1] == 'Y') {
        while (i < len && s[i] >= '0' && s[i] <= '9')
          i++;
      }
      break;

    case '#': /* extended glob qualifiers */
      i++;
      if (i < len) {
        /* (#i), (#b), (#a), etc. */
        i++; /* skip qualifier letter */
        if (i < len && s[i] >= '0' && s[i] <= '9') {
          while (i < len && s[i] >= '0' && s[i] <= '9')
            i++;
        }
      }
      break;

    default:
      i++; /* skip unknown */
      break;
    }

    quals[nqual++] = q;
  }

  return nqual;
}

/* Parse a complete glob pattern to extract the qualifier portion */
static void parse_glob_with_qualifiers(const char *pattern, size_t len) {
  if (len == 0)
    return;

  /* Find the last '(' that could start qualifiers */
  size_t last_open = 0;
  int found = 0;
  int depth = 0;

  for (size_t i = len; i > 0; i--) {
    if (pattern[i - 1] == ')' && depth == 0) {
      /* Find matching open paren */
      for (size_t j = i - 1; j > 0; j--) {
        if (pattern[j - 1] == '(') {
          last_open = j - 1;
          found = 1;
          break;
        }
      }
      if (found)
        break;
    }
  }

  if (found && last_open < len) {
    GlobQualifier quals[MAX_QUALIFIERS];
    parse_qualifiers(pattern + last_open, len - last_open, quals,
                     MAX_QUALIFIERS);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 2048)
    return 0;

  /* Null-terminate */
  char *pattern = (char *)malloc(size + 1);
  if (!pattern)
    return 0;
  memcpy(pattern, data, size);
  pattern[size] = '\0';

  parse_glob_with_qualifiers(pattern, size);

  free(pattern);
  return 0;
}

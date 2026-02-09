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
 * Fuzz nmap's service probe file parsing.
 *
 * Nmap's nmap-service-probes file defines probe strings and match
 * directives used for service/version detection. The file format has
 * a custom syntax with regex patterns, making it a good fuzz target.
 *
 * Format example:
 *   Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
 *   match http m|^HTTP/1\.[01] \d\d\d| p/Apache/ v/2.4/
 *   softmatch ssl m|^\x16\x03| p/SSL/
 *
 * This fuzzer implements standalone parsing of these probe definitions.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

struct MatchDirective {
  std::string service_name;
  std::string regex_pattern;
  std::string product;
  std::string version;
  bool is_soft;
};

struct ProbeDefinition {
  std::string protocol; /* TCP or UDP */
  std::string name;
  std::string probe_string;
  std::vector<MatchDirective> matches;
  int rarity;
  int totalwaitms;
  std::vector<int> ports;
};

/* Parse a quoted string with escape sequences (q|...|) */
static std::string parse_quoted_string(const char *s, size_t len) {
  std::string result;
  if (len < 3)
    return result;

  /* Find the delimiter character */
  char delim = s[1]; /* e.g., '|' in q|...|  */
  size_t start = 2;
  size_t end = len;

  /* Find closing delimiter */
  for (size_t i = start; i < len; i++) {
    if (s[i] == delim) {
      end = i;
      break;
    }
  }

  for (size_t i = start; i < end; i++) {
    if (s[i] == '\\' && i + 1 < end) {
      i++;
      switch (s[i]) {
      case 'n':
        result += '\n';
        break;
      case 'r':
        result += '\r';
        break;
      case 't':
        result += '\t';
        break;
      case '\\':
        result += '\\';
        break;
      case '0':
        result += '\0';
        break;
      case 'x':
        if (i + 2 < end) {
          char hex[3] = {s[i + 1], s[i + 2], 0};
          result += (char)strtol(hex, NULL, 16);
          i += 2;
        }
        break;
      default:
        result += s[i];
        break;
      }
    } else {
      result += s[i];
    }
  }

  return result;
}

/* Parse a match line: "match <service> m|<regex>| [p/product/ v/version/]" */
static MatchDirective parse_match_line(const char *line, size_t len) {
  MatchDirective md = {};

  if (len < 8)
    return md;

  const char *p = line;
  const char *end = line + len;

  /* Skip "match" or "softmatch" */
  if (strncmp(p, "softmatch", 9) == 0) {
    md.is_soft = true;
    p += 9;
  } else if (strncmp(p, "match", 5) == 0) {
    md.is_soft = false;
    p += 5;
  } else {
    return md;
  }

  /* Skip whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Read service name */
  const char *svc_start = p;
  while (p < end && *p != ' ' && *p != '\t')
    p++;
  md.service_name = std::string(svc_start, p - svc_start);

  /* Skip whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Parse regex: m|...|  or m/.../ */
  if (p < end && *p == 'm' && p + 1 < end) {
    char delim = p[1];
    p += 2;
    const char *regex_start = p;
    while (p < end && *p != delim) {
      if (*p == '\\' && p + 1 < end)
        p++; /* skip escaped chars */
      p++;
    }
    md.regex_pattern = std::string(regex_start, p - regex_start);
    if (p < end)
      p++; /* skip closing delimiter */
  }

  /* Parse optional flags: p/product/ v/version/ */
  while (p < end) {
    while (p < end && (*p == ' ' || *p == '\t'))
      p++;

    if (p >= end)
      break;

    if (*p == 'p' && p + 1 < end && p[1] == '/') {
      p += 2;
      const char *val_start = p;
      while (p < end && *p != '/')
        p++;
      md.product = std::string(val_start, p - val_start);
      if (p < end)
        p++;
    } else if (*p == 'v' && p + 1 < end && p[1] == '/') {
      p += 2;
      const char *val_start = p;
      while (p < end && *p != '/')
        p++;
      md.version = std::string(val_start, p - val_start);
      if (p < end)
        p++;
    } else {
      p++;
    }
  }

  return md;
}

/* Parse a Probe line: "Probe TCP|UDP <name> q|<string>|" */
static ProbeDefinition parse_probe_line(const char *line, size_t len) {
  ProbeDefinition pd = {};

  if (len < 10)
    return pd;

  const char *p = line;
  const char *end = line + len;

  /* Skip "Probe " */
  if (strncmp(p, "Probe", 5) != 0)
    return pd;
  p += 5;

  /* Skip whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Read protocol */
  const char *proto_start = p;
  while (p < end && *p != ' ' && *p != '\t')
    p++;
  pd.protocol = std::string(proto_start, p - proto_start);

  /* Skip whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Read probe name */
  const char *name_start = p;
  while (p < end && *p != ' ' && *p != '\t')
    p++;
  pd.name = std::string(name_start, p - name_start);

  /* Skip whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Parse probe string */
  if (p < end) {
    pd.probe_string = parse_quoted_string(p, end - p);
  }

  return pd;
}

/* Parse a ports line: "ports 21,22,23,25,80" */
static std::vector<int> parse_ports_line(const char *line, size_t len) {
  std::vector<int> ports;

  if (len < 6)
    return ports;

  const char *p = line;
  const char *end = line + len;

  if (strncmp(p, "ports", 5) != 0)
    return ports;
  p += 5;

  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  while (p < end) {
    long port = strtol(p, NULL, 10);
    if (port > 0 && port <= 65535)
      ports.push_back((int)port);

    /* Skip to next comma or end */
    while (p < end && *p != ',')
      p++;
    if (p < end)
      p++; /* skip comma */
  }

  return ports;
}

/* Full probe-file parser */
static void parse_probe_file(const char *data, size_t size) {
  const char *p = data;
  const char *end = data + size;

  while (p < end) {
    /* Find line end */
    const char *line_end = p;
    while (line_end < end && *line_end != '\n')
      line_end++;

    size_t line_len = line_end - p;

    /* Skip comments and blank lines */
    if (line_len == 0 || *p == '#') {
      p = (line_end < end) ? line_end + 1 : end;
      continue;
    }

    /* Parse based on line type */
    if (strncmp(p, "Probe ", 6) == 0) {
      parse_probe_line(p, line_len);
    } else if (strncmp(p, "match ", 6) == 0 ||
               strncmp(p, "softmatch ", 10) == 0) {
      parse_match_line(p, line_len);
    } else if (strncmp(p, "ports ", 6) == 0) {
      parse_ports_line(p, line_len);
    } else if (strncmp(p, "rarity ", 7) == 0) {
      /* Just parse the number */
      strtol(p + 7, NULL, 10);
    } else if (strncmp(p, "totalwaitms ", 12) == 0) {
      strtol(p + 12, NULL, 10);
    }

    p = (line_end < end) ? line_end + 1 : end;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 65536)
    return 0;

  /* Ensure null-terminated */
  char *buf = (char *)malloc(size + 1);
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  parse_probe_file(buf, size);

  free(buf);
  return 0;
}

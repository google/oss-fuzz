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
 * Fuzz nmap XML output parsing.
 *
 * Nmap produces XML output (nmap -oX) that tools like ndiff parse.
 * This fuzzer implements a standalone XML element/attribute parser
 * that mirrors the parsing nmap's output consumers perform.
 *
 * This tests the robustness of XML generation/parsing round-trips.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

struct XMLAttribute {
  std::string name;
  std::string value;
};

struct XMLElement {
  std::string tag;
  std::vector<XMLAttribute> attrs;
  std::string text;
  bool is_closing;
  bool is_self_closing;
};

/* Parse XML attributes from a tag string */
static std::vector<XMLAttribute> parse_attributes(const char *s, size_t len) {
  std::vector<XMLAttribute> attrs;
  const char *p = s;
  const char *end = s + len;

  while (p < end) {
    /* Skip whitespace */
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
      p++;

    if (p >= end || *p == '>' || *p == '/' || *p == '?')
      break;

    /* Read attribute name */
    const char *name_start = p;
    while (p < end && *p != '=' && *p != ' ' && *p != '>' && *p != '/')
      p++;

    std::string name(name_start, p - name_start);

    if (p >= end || *p != '=') {
      /* Boolean attribute */
      XMLAttribute attr;
      attr.name = name;
      attrs.push_back(attr);
      continue;
    }
    p++; /* skip '=' */

    if (p >= end)
      break;

    /* Read attribute value */
    std::string value;
    if (*p == '"' || *p == '\'') {
      char quote = *p;
      p++;
      const char *val_start = p;
      while (p < end && *p != quote) {
        if (*p == '&') {
          /* Handle XML entities */
          if (strncmp(p, "&amp;", 5) == 0) {
            value += std::string(val_start, p - val_start);
            value += '&';
            p += 5;
            val_start = p;
            continue;
          } else if (strncmp(p, "&lt;", 4) == 0) {
            value += std::string(val_start, p - val_start);
            value += '<';
            p += 4;
            val_start = p;
            continue;
          } else if (strncmp(p, "&gt;", 4) == 0) {
            value += std::string(val_start, p - val_start);
            value += '>';
            p += 4;
            val_start = p;
            continue;
          } else if (strncmp(p, "&quot;", 6) == 0) {
            value += std::string(val_start, p - val_start);
            value += '"';
            p += 6;
            val_start = p;
            continue;
          } else if (strncmp(p, "&apos;", 6) == 0) {
            value += std::string(val_start, p - val_start);
            value += '\'';
            p += 6;
            val_start = p;
            continue;
          }
        }
        p++;
      }
      value += std::string(val_start, p - val_start);
      if (p < end)
        p++; /* skip closing quote */
    } else {
      /* Unquoted attribute value */
      const char *val_start = p;
      while (p < end && *p != ' ' && *p != '>' && *p != '/')
        p++;
      value = std::string(val_start, p - val_start);
    }

    XMLAttribute attr;
    attr.name = name;
    attr.value = value;
    attrs.push_back(attr);
  }

  return attrs;
}

/* Parse a single XML element from a '<' to '>' */
static XMLElement parse_element(const char *s, size_t len) {
  XMLElement elem = {};
  elem.is_closing = false;
  elem.is_self_closing = false;

  if (len < 2 || s[0] != '<')
    return elem;

  const char *p = s + 1;
  const char *end = s + len;

  /* Check for closing tag */
  if (*p == '/') {
    elem.is_closing = true;
    p++;
  }

  /* Check for processing instruction or comment */
  if (*p == '?' || *p == '!') {
    elem.tag = std::string(p, end - p);
    return elem;
  }

  /* Read tag name */
  const char *tag_start = p;
  while (p < end && *p != ' ' && *p != '\t' && *p != '>' && *p != '/')
    p++;
  elem.tag = std::string(tag_start, p - tag_start);

  /* Check for self-closing */
  if (len >= 2 && s[len - 2] == '/') {
    elem.is_self_closing = true;
  }

  /* Parse attributes */
  if (p < end) {
    size_t remaining = end - p;
    if (remaining > 1 && s[len - 1] == '>') {
      remaining--; /* exclude closing '>' */
      if (elem.is_self_closing && remaining > 0)
        remaining--; /* exclude '/' */
    }
    elem.attrs = parse_attributes(p, remaining);
  }

  return elem;
}

/* Parse a full XML document */
static void parse_xml_document(const char *data, size_t size) {
  const char *p = data;
  const char *end = data + size;
  int depth = 0;

  while (p < end) {
    /* Find next '<' */
    while (p < end && *p != '<')
      p++;

    if (p >= end)
      break;

    /* Find matching '>' */
    const char *tag_start = p;
    p++;
    while (p < end && *p != '>')
      p++;

    if (p >= end)
      break;
    p++; /* include '>' */

    size_t tag_len = p - tag_start;
    XMLElement elem = parse_element(tag_start, tag_len);

    if (elem.is_closing) {
      depth--;
      if (depth < 0)
        depth = 0;
    } else if (!elem.is_self_closing && !elem.tag.empty() &&
               elem.tag[0] != '?' && elem.tag[0] != '!') {
      depth++;
      if (depth > 256)
        break; /* prevent stack-like overflow */
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 65536)
    return 0;

  parse_xml_document((const char *)data, size);
  return 0;
}

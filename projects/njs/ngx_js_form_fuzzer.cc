// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

extern "C" {
#include "ngx_core.h"
#include "ngx_js_form.h"
}

namespace {

struct ParsedInput {
  std::string content_type;
  std::string boundary;
  std::string body;
  ngx_uint_t max_keys;
};

int HexValue(unsigned char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }

  c = static_cast<unsigned char>(c | 0x20);
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }

  return -1;
}

std::string Unescape(const char *s, size_t n) {
  std::string out;
  out.reserve(n);

  for (size_t i = 0; i < n; i++) {
    unsigned char c = static_cast<unsigned char>(s[i]);

    if (c != '\\' || i + 1 >= n) {
      out.push_back(static_cast<char>(c));
      continue;
    }

    unsigned char esc = static_cast<unsigned char>(s[++i]);
    switch (esc) {
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case '\\':
        out.push_back('\\');
        break;
      case 'x':
        if (i + 2 < n) {
          int h1 = HexValue(static_cast<unsigned char>(s[i + 1]));
          int h2 = HexValue(static_cast<unsigned char>(s[i + 2]));
          if (h1 >= 0 && h2 >= 0) {
            out.push_back(static_cast<char>((h1 << 4) | h2));
            i += 2;
            break;
          }
        }
        out.push_back('x');
        break;
      default:
        out.push_back(static_cast<char>(esc));
        break;
    }
  }

  return out;
}

ParsedInput ParseSeedText(const uint8_t *data, size_t size) {
  ParsedInput in;
  in.content_type = "application/x-www-form-urlencoded";
  in.boundary = "X";
  in.max_keys = 128;
  in.body.assign(reinterpret_cast<const char *>(data), size);

  if (size < 3 || memcmp(data, "CT:", 3) != 0) {
    return in;
  }

  const char *buf = reinterpret_cast<const char *>(data);
  const char *end = buf + size;
  const char *p = buf;

  in.body.clear();

  while (p < end) {
    const char *line_end =
        static_cast<const char *>(memchr(p, '\n', static_cast<size_t>(end - p)));
    if (line_end == nullptr) {
      line_end = end;
    }

    size_t line_len = static_cast<size_t>(line_end - p);

    if (line_len >= 3 && memcmp(p, "CT:", 3) == 0) {
      std::string v = Unescape(p + 3, line_len - 3);
      if (!v.empty()) {
        if (v == "urlencoded") {
          in.content_type = "application/x-www-form-urlencoded";
        } else if (v == "multipart") {
          in.content_type = "multipart/form-data";
        } else {
          in.content_type = v;
        }
      }
    } else if (line_len >= 4 && memcmp(p, "MAX:", 4) == 0) {
      unsigned long long n = 0;
      for (size_t i = 4; i < line_len; i++) {
        unsigned char c = static_cast<unsigned char>(p[i]);
        if (c < '0' || c > '9') {
          n = 0;
          break;
        }
        n = (n * 10) + (c - '0');
        if (n > 0xffffffffULL) {
          n = 0xffffffffULL;
          break;
        }
      }
      in.max_keys = static_cast<ngx_uint_t>(n == 0 ? 1 : n);
    } else if (line_len >= 9 && memcmp(p, "BOUNDARY:", 9) == 0) {
      in.boundary = Unescape(p + 9, line_len - 9);
    } else if (line_len >= 5 && memcmp(p, "BODY:", 5) == 0) {
      in.body = Unescape(p + 5, line_len - 5);
      if (line_end < end) {
        const char *rest = line_end + 1;
        if (rest < end) {
          in.body.append(Unescape(rest, static_cast<size_t>(end - rest)));
        }
      }
      return in;
    }

    p = (line_end < end) ? (line_end + 1) : end;
  }

  return in;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr) {
    return 0;
  }

  ParsedInput in = ParseSeedText(data, size);

  std::string ct_string = in.content_type;
  if (ct_string == "multipart/form-data") {
    ct_string += "; boundary=";
    ct_string += in.boundary;
  }

  ngx_pool_t *pool = ngx_create_pool(0);
  if (pool == nullptr) {
    return 0;
  }

  ngx_str_t content_type;
  content_type.len = ct_string.size();
  content_type.data = reinterpret_cast<u_char *>(
      ngx_pnalloc(pool, content_type.len == 0 ? 1 : content_type.len));
  if (content_type.data == nullptr) {
    ngx_destroy_pool(pool);
    return 0;
  }
  if (content_type.len != 0) {
    memcpy(content_type.data, ct_string.data(), content_type.len);
  }

  size_t body_len = in.body.size();
  u_char *body =
      reinterpret_cast<u_char *>(ngx_pnalloc(pool, body_len == 0 ? 1 : body_len));
  if (body == nullptr) {
    ngx_destroy_pool(pool);
    return 0;
  }
  if (body_len != 0) {
    memcpy(body, in.body.data(), body_len);
  }

  ngx_str_t err;
  ngx_js_form_t *form = nullptr;

  (void)ngx_js_parse_form(pool, &content_type, body, body_len, in.max_keys, &form,
                          &err);

  ngx_destroy_pool(pool);
  return 0;
}

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
 * Fuzz LDAP URL parsing (RFC 4516).
 *
 * LDAP URLs have the format:
 *   ldap://host:port/dn?attrs?scope?filter?exts
 *
 * Examples:
 *   ldap://ldap.example.com/dc=example,dc=com
 *   ldap:///dc=example,dc=com??sub?(objectClass=*)
 *   ldaps://ldap.example.com:636/ou=People,dc=example,dc=com?cn,sn?one
 *   ldapi://%2Fvar%2Frun%2Fldapi/
 *
 * This fuzzer parses LDAP URL components independently of libldap.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_URL_COMPONENT 1024

typedef struct {
  char scheme[16];    /* ldap, ldaps, ldapi */
  char host[MAX_URL_COMPONENT];
  int port;
  char dn[MAX_URL_COMPONENT];
  char attrs[MAX_URL_COMPONENT];
  char scope[16];     /* base, one, sub, children */
  char filter[MAX_URL_COMPONENT];
  char extensions[MAX_URL_COMPONENT];
  int is_critical_ext;
} LDAPUrl;

/* Percent-decode a URL component */
static int url_decode(const char *src, size_t src_len, char *dst,
                      size_t dst_max) {
  size_t si = 0, di = 0;

  while (si < src_len && di < dst_max - 1) {
    if (src[si] == '%' && si + 2 < src_len) {
      int h = -1, l = -1;

      if (src[si + 1] >= '0' && src[si + 1] <= '9')
        h = src[si + 1] - '0';
      else if (src[si + 1] >= 'a' && src[si + 1] <= 'f')
        h = src[si + 1] - 'a' + 10;
      else if (src[si + 1] >= 'A' && src[si + 1] <= 'F')
        h = src[si + 1] - 'A' + 10;

      if (src[si + 2] >= '0' && src[si + 2] <= '9')
        l = src[si + 2] - '0';
      else if (src[si + 2] >= 'a' && src[si + 2] <= 'f')
        l = src[si + 2] - 'a' + 10;
      else if (src[si + 2] >= 'A' && src[si + 2] <= 'F')
        l = src[si + 2] - 'A' + 10;

      if (h >= 0 && l >= 0) {
        dst[di++] = (char)((h << 4) | l);
        si += 3;
        continue;
      }
    }
    dst[di++] = src[si++];
  }

  dst[di] = '\0';
  return (int)di;
}

/* Parse an LDAP URL */
static int parse_ldap_url(const char *url, size_t len, LDAPUrl *result) {
  memset(result, 0, sizeof(*result));
  result->port = -1;

  if (len == 0)
    return -1;

  const char *p = url;
  const char *end = url + len;

  /* Parse scheme */
  const char *scheme_end = strstr(p, "://");
  if (!scheme_end || scheme_end >= end)
    return -1;

  size_t scheme_len = scheme_end - p;
  if (scheme_len >= sizeof(result->scheme))
    scheme_len = sizeof(result->scheme) - 1;
  memcpy(result->scheme, p, scheme_len);
  result->scheme[scheme_len] = '\0';

  /* Validate scheme */
  if (strcmp(result->scheme, "ldap") != 0 &&
      strcmp(result->scheme, "ldaps") != 0 &&
      strcmp(result->scheme, "ldapi") != 0 &&
      strcmp(result->scheme, "cldap") != 0) {
    return -1;
  }

  p = scheme_end + 3; /* skip "://" */

  /* Parse host[:port] */
  const char *path_start = strchr(p, '/');
  if (!path_start)
    path_start = end;

  const char *host_end = path_start;
  size_t hostport_len = host_end - p;

  if (hostport_len > 0) {
    /* Check for IPv6 bracket notation */
    if (*p == '[') {
      const char *bracket_end = memchr(p, ']', hostport_len);
      if (bracket_end) {
        size_t host_len = bracket_end - p - 1;
        if (host_len >= MAX_URL_COMPONENT)
          host_len = MAX_URL_COMPONENT - 1;
        memcpy(result->host, p + 1, host_len);
        result->host[host_len] = '\0';

        if (bracket_end + 1 < host_end && bracket_end[1] == ':') {
          result->port = atoi(bracket_end + 2);
        }
      }
    } else {
      /* Regular host:port */
      const char *colon = memchr(p, ':', hostport_len);
      if (colon) {
        size_t host_len = colon - p;
        if (host_len >= MAX_URL_COMPONENT)
          host_len = MAX_URL_COMPONENT - 1;
        url_decode(p, host_len, result->host, MAX_URL_COMPONENT);
        result->port = atoi(colon + 1);
      } else {
        url_decode(p, hostport_len, result->host, MAX_URL_COMPONENT);
      }
    }
  }

  if (path_start >= end)
    return 0;

  p = path_start + 1; /* skip '/' */

  /* Parse DN (up to first '?') */
  const char *q1 = memchr(p, '?', end - p);
  if (!q1)
    q1 = end;

  url_decode(p, q1 - p, result->dn, MAX_URL_COMPONENT);
  if (q1 >= end)
    return 0;

  p = q1 + 1;

  /* Parse attributes (up to next '?') */
  const char *q2 = memchr(p, '?', end - p);
  if (!q2)
    q2 = end;

  url_decode(p, q2 - p, result->attrs, MAX_URL_COMPONENT);
  if (q2 >= end)
    return 0;

  p = q2 + 1;

  /* Parse scope */
  const char *q3 = memchr(p, '?', end - p);
  if (!q3)
    q3 = end;

  size_t scope_len = q3 - p;
  if (scope_len >= sizeof(result->scope))
    scope_len = sizeof(result->scope) - 1;
  memcpy(result->scope, p, scope_len);
  result->scope[scope_len] = '\0';

  if (q3 >= end)
    return 0;

  p = q3 + 1;

  /* Parse filter */
  const char *q4 = memchr(p, '?', end - p);
  if (!q4)
    q4 = end;

  url_decode(p, q4 - p, result->filter, MAX_URL_COMPONENT);
  if (q4 >= end)
    return 0;

  p = q4 + 1;

  /* Parse extensions */
  url_decode(p, end - p, result->extensions, MAX_URL_COMPONENT);

  /* Check for critical extension marker '!' */
  if (result->extensions[0] == '!')
    result->is_critical_ext = 1;

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 7 || size > 4096) /* minimum: "ldap://" */
    return 0;

  char *str = (char *)malloc(size + 1);
  if (!str)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  LDAPUrl url;
  parse_ldap_url(str, size, &url);

  free(str);
  return 0;
}

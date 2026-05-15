#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include "uv.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Ensure we have a null-terminated string for parsing functions
  std::vector<char> null_terminated_str(data, data + size);
  null_terminated_str.push_back('\0');
  const char* ip_str = null_terminated_str.data();

  // 1. Test IPv4 parsing
  struct in_addr addr4;
  if (uv_inet_pton(AF_INET, ip_str, &addr4) == 0) {
    // If parsing succeeds, validate that we can convert it back to a string
    char dst4[INET_ADDRSTRLEN];
    uv_inet_ntop(AF_INET, &addr4, dst4, sizeof(dst4));
  }

  // 2. Test IPv6 parsing
  struct in6_addr addr6;
  if (uv_inet_pton(AF_INET6, ip_str, &addr6) == 0) {
    // If parsing succeeds, validate that we can convert it back to a string
    char dst6[INET6_ADDRSTRLEN];
    uv_inet_ntop(AF_INET6, &addr6, dst6, sizeof(dst6));
  }

  return 0;
}

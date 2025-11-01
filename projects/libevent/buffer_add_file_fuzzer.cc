/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/buffer_compat.h"
#include "libevent/include/event2/event.h"
#include "libevent/include/event2/util.h"
#include "util-internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider data_provider(data, size);

  std::string s1 = data_provider.ConsumeRandomLengthString();
  uint32_t int1 = data_provider.ConsumeIntegral<uint32_t>();

  char bufferFile[50];
  struct stat st;

  sprintf(bufferFile, "/tmp/buffer.%d", getpid());
  FILE *fp = fopen(bufferFile, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(s1.c_str(), s1.size(), 1, fp);
  fclose(fp);

  fp = fopen(bufferFile, "rb");
  if (!fp) {
    return 0;
  }

  int fd = fileno(fp);
  fstat(fd, &st);

  struct evbuffer *buf = evbuffer_new();
  evbuffer_set_flags(buf, int1);
  evbuffer_add_file(buf, fd, 0, st.st_size);

  fclose(fp);
  close(fd);

  unlink(bufferFile);
  evbuffer_free(buf);
  return 0;
}

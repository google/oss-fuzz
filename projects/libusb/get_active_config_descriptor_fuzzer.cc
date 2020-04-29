// Copyright 2020 Google LLC
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

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "libusb/libusb.h"
#include "libusb/libusbi.h"

static unsigned char *data_;
static size_t size_;

int fuzzer_get_active_config_descriptor(struct libusb_device *device,
                                        unsigned char *buffer, size_t len,
                                        int *host_endian) {
  buffer = data_;
  return std::min(len, size_);
}

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
const struct usbi_os_backend usbi_backend = {
    .get_active_config_descriptor = fuzzer_get_active_config_descriptor,
};
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  data_ = (unsigned char *)data;
  size_ = size;

  struct libusb_config_descriptor *config = nullptr;
  libusb_get_active_config_descriptor(nullptr, &config);
  libusb_free_config_descriptor(config);

  return 0;
}

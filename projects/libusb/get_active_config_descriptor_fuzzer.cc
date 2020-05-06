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
#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "libusb/libusb.h"
#include "libusb/libusbi.h"

/*static unsigned char *data_;
static size_t size_;*/

/*int fuzzer_get_active_config_descriptor(struct libusb_device *device,
                                        unsigned char *buffer, size_t len,
                                        int *host_endian) {
  buffer = data_;
  return std::min(len, size_);
}

const struct usbi_os_backend usbi_backend = {
    .get_active_config_descriptor = fuzzer_get_active_config_descriptor,
};*/

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
/*  data_ = (unsigned char *)data;
  size_ = size;*/
  FuzzedDataProvider stream(data, size);
  uint8_t bmRequestType = stream.ConsumeIntegral<uint8_t>();
  uint8_t bRequest = stream.ConsumeIntegral<uint8_t>();
  uint16_t wValue = stream.ConsumeIntegral<uint16_t>();
  uint16_t wIndex = stream.ConsumeIntegral<uint16_t>();
  uint16_t wLength = stream.ConsumeIntegral<uint16_t>();
  std::vector<char> data_ = stream.ConsumeRemainingBytes<char>();

  libusb_fill_control_setup(reinterpret_cast<unsigned char*>(data_.data()),
    bmRequestType, bRequest, wValue, wIndex, wLength);

/*  int r;
  libusb_device_handle *dev_handle;

  r = libusb_get_string_descriptor(nullptr, 0, 0, buffer, sizeof(buffer));

  if (r < 4){
    return LIBUSB_ERROR_IO;
  }*/

/*  struct libusb_config_descriptor *config = nullptr;
  libusb_get_active_config_descriptor(nullptr, &config);
  libusb_free_config_descriptor(config);*/

  return 0;
}

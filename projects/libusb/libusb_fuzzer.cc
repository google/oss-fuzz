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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct libusb_transfer *transfer;
  FuzzedDataProvider stream(data, size);
  uint8_t bmRequestType = stream.ConsumeIntegral<uint8_t>();
  uint8_t bRequest = stream.ConsumeIntegral<uint8_t>();
  uint16_t wValue = stream.ConsumeIntegral<uint16_t>();
  uint16_t wIndex = stream.ConsumeIntegral<uint16_t>();
  uint16_t wLength = stream.ConsumeIntegral<uint16_t>();
  std::vector<char> data_ = stream.ConsumeRemainingBytes<char>();
  unsigned char* buffer = reinterpret_cast<unsigned char*>(data_.data());

  transfer = libusb_alloc_transfer(0);
  if (!transfer) {
    return LIBUSB_ERROR_NO_MEM;
  }

  if (!buffer) {
    libusb_free_transfer(transfer);
    return LIBUSB_ERROR_NO_MEM;
  }

  libusb_fill_control_setup(
    buffer, bmRequestType, bRequest, wValue, wIndex, wLength);

  libusb_free_transfer(transfer);
  return 0;
}

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
  struct libusb_transfer *transfer = NULL;
  FuzzedDataProvider stream(data, size);
  uint8_t bmRequestType = stream.ConsumeIntegral<uint8_t>();
  uint8_t bRequest = stream.ConsumeIntegral<uint8_t>();
  uint16_t wValue = stream.ConsumeIntegral<uint16_t>();
  uint16_t wIndex = stream.ConsumeIntegral<uint16_t>();
  uint16_t wLength = stream.ConsumeIntegral<uint16_t>();
  std::string input = stream.ConsumeRandomLengthString();
  const char *d = input.c_str();

  transfer = libusb_alloc_transfer(0);
  if (!transfer) {
    return LIBUSB_ERROR_NO_MEM;
  }

  libusb_fill_control_setup((unsigned char *)d, bmRequestType, bRequest, wValue, wIndex, wLength);

  // Cleanup. 
  // We cannot call libusb_free_transfer as no callbacks has occurred. Calling
  // libusb_free_transfer without this will trigger false positive errors.
  struct usbi_transfer *itransfer = LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
  usbi_mutex_destroy(&itransfer->lock);
  size_t priv_size = PTR_ALIGN(usbi_backend.transfer_priv_size);
  unsigned char *ptr = (unsigned char *)itransfer - priv_size;
  free(ptr);

  return 0;
}

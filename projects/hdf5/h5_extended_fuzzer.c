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

#include "hdf5.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    hid_t fuzz_h5_id = H5Fopen(filename, H5F_ACC_RDWR, H5P_DEFAULT);
    if (fuzz_h5_id != H5I_INVALID_HID) {
      hid_t  dataset_id = H5Dopen2(fuzz_h5_id, "dsetname", H5P_DEFAULT);
      if (dataset_id != H5I_INVALID_HID) {
          hid_t attribute_id = H5Aopen_name(dataset_id, "theattr");
          if (attribute_id != H5I_INVALID_HID) {
            H5Aclose(attribute_id);
          }
          H5Dclose(dataset_id);
      }
      H5Fclose(fuzz_h5_id);
    }
    return 0;
}

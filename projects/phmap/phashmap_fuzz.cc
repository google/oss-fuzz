/* Copyright 2021 Google LLC
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
#include <iostream>
#include <bitset>
#include <cinttypes>
#include <unistd.h>
#include "parallel_hashmap/phmap_dump.h"
#include <fuzzer/FuzzedDataProvider.h>

using phmap::flat_hash_map;
using namespace std;

void serialise_test(const uint8_t *data, size_t size) {
    phmap::flat_hash_map<unsigned int, int> table;
    FuzzedDataProvider fuzzed_data(data, size);
    const int num_items = fuzzed_data.ConsumeIntegral<int16_t>();

    for (int i=0; i < num_items; ++i)  {
        table.insert(typename phmap::flat_hash_map<unsigned int, int>::value_type(
                    fuzzed_data.ConsumeIntegral<uint32_t>(), 
                    fuzzed_data.ConsumeIntegral<int32_t>()));
    }

    phmap::BinaryOutputArchive ar_out("/dump.data");
    table.phmap_dump(ar_out);

    //MapType table_in;
    phmap::flat_hash_map<unsigned int, int> table_in;
    phmap::BinaryInputArchive ar_in("/dump.data");
    table_in.phmap_load(ar_in);

    if(table == table_in) {
        unlink("/dump.data");
        return;
    }
    unlink("/dump.data");
}

void
test_assignments(const uint8_t *data, size_t size) {
    phmap::flat_hash_map<std::string, std::string> email;
    FuzzedDataProvider fuzzed_data(data, size);
    const int num_items = fuzzed_data.ConsumeIntegral<int16_t>();
    for (int i=0; i < num_items; ++i) {
            phmap::flat_hash_map<std::string, std::string>::value_type(
                    fuzzed_data.ConsumeRandomLengthString(), 
                    fuzzed_data.ConsumeRandomLengthString());
    }
    // Iterate through all of the items.
    for (const auto& n: email) {}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    serialise_test(data, size);
    test_assignments(data, size);
    return 0;
}

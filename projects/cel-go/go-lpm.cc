// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "fuzzlpm/cel-go-lpm.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

extern "C" void  LPMFuzzerTestOneInput(const uint8_t *buffer, size_t size);

DEFINE_PROTO_FUZZER(const celgolpm::FuzzVariables& input) {
    size_t size = input.ByteSizeLong();
    if (size > 0) {
        uint8_t *buffer = (uint8_t *) malloc(size);
        //printf("debugs %d: %s\n", size, input.DebugString().c_str());
        input.SerializeToArray((uint8_t *) buffer, size);
        LPMFuzzerTestOneInput(buffer, size);
        free(buffer);
    }
}

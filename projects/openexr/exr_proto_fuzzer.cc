// Copyright 2025 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "exr.pb.h"

#include <ImfNamespace.h>
#include <ImfCheckFile.h>
#include <string>

#include "exr_proto_converter.h"

DEFINE_PROTO_FUZZER(const ExrProto &exr) {
    std::string data = ProtoToExr(exr);

    Imf::checkOpenEXRFile (data.c_str() , data.size() , true , true , true);
    return;
}
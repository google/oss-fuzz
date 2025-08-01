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

#ifndef EXR_PROTO_CONVERTER_H
#define EXR_PROTO_CONVERTER_H

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "exr.pb.h"

#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <algorithm>

std::string ProtoToExr(const ExrProto &exr_proto);

#endif // EXR_PROTO_CONVERTER_H
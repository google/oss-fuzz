// Copyright 2020 Google Inc.
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

#include "absl/flags/commandlineflag.h"
#include "absl/flags/marshalling.h"
#include "absl/flags/parse.h"

#include <memory>
#include <string>
#include <stdint.h>
#include <cmath>
#include <limits>
#include <vector>
#include <fstream>
#include <iostream>

#include "absl/flags/flag.h"
#include "absl/flags/internal/usage.h"
#include "absl/flags/reflection.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/types/span.h"
#include "absl/flags/flag.h"
#include "absl/flags/internal/private_handle_accessor.h"
#include "absl/flags/usage_config.h"
#include "absl/memory/memory.h"
#include "absl/strings/match.h"

ABSL_FLAG(std::string, string_flag, "", "string flag");
ABSL_FLAG(int, int_flag, 1234, "int flag");

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10)
    {
        return 0;
    }

    std::string str (reinterpret_cast<const char*>(data), size);
    char* args = (char*)malloc(size);
    memcpy(args, data, size);
    args[size-1] = '\0';
    absl::ParseCommandLine(1, (char**)&args);

    absl::SetFlag(&FLAGS_int_flag, (int)*data);
    absl::SetFlag(&FLAGS_string_flag, str);
    auto* flag_01 = absl::FindCommandLineFlag("int_flag");
    auto* flag_02 = absl::FindCommandLineFlag("string_flag");
    flag_01->Name();
    flag_01->Help();
    flag_01->IsRetired();
    flag_01->IsOfType<int>();
    flag_01->IsOfType<bool>();
    flag_01->IsOfType<std::string>();
    absl::EndsWith(flag_01->Filename(), args);

    flag_02->Name();
    flag_02->Help();
    flag_02->IsRetired();
    flag_02->IsOfType<int>();
    flag_02->IsOfType<bool>();
    flag_02->IsOfType<std::string>();
    absl::EndsWith(flag_02->Filename(), args);

    auto* flag_011 = absl::FindCommandLineFlag(args);
    auto* flag_022 = absl::FindCommandLineFlag(args);
    if (flag_011)
    {
        flag_011->CurrentValue();
        flag_011->DefaultValue();
    }
    if (flag_022)
    {
        flag_022->CurrentValue();
        flag_022->DefaultValue();
    }
    

    absl::GetFlag(FLAGS_int_flag);
    absl::GetFlag(FLAGS_string_flag);

    std::string err;
    std::string value1;
    bool value2;
    int16_t value3;
    uint16_t value4;
    uint32_t value5;
    int32_t value6;
    absl::ParseFlag(args, &value1, &err);
    absl::ParseFlag(args, &value2, &err);
    absl::ParseFlag(args, &value3, &err);
    absl::ParseFlag(args, &value4, &err);
    absl::ParseFlag(args, &value5, &err);
    absl::ParseFlag(args, &value6, &err);

    absl::flags_internal::GetMisspellingHints(args);

    std::vector<char*> positional_args;
    std::vector<absl::UnrecognizedFlag> unrecognized_flags;
    absl::ParseAbseilFlagsOnly(1, (char**)&args, positional_args,
                             unrecognized_flags);
        free(args);
        return 0;
}
// Copyright 2022 Code Intelligence GmbH
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

#pragma once

#include <napi.h>

// Export fuzzer callbacks.
//
// Add all our fuzzer callback functions to the list of the module's exports;
// these functions let JS target code provide feedback to libfuzzer or the
// native agent.
void RegisterCallbackExports(Napi::Env env, Napi::Object exports);

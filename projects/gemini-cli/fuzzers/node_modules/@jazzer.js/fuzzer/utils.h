// Copyright 2022 Code Intelligence GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#pragma once

#include <napi.h>
// Definitions from compiler-rt, including libfuzzer's entrypoint and the
// sanitizer runtime initialization function.
#include <fuzzer/FuzzerDefs.h>

void StartLibFuzzer(const std::vector<std::string> &args,
                    fuzzer::UserCallback fuzzCallback);
std::vector<std::string> LibFuzzerArgs(Napi::Env env,
                                       const Napi::Array &jsArgs);

int StopFuzzingHandleExit(const Napi::CallbackInfo &info);
void AsyncReturnsHandler();
void SyncReturnsHandler();
void ReturnValueInfo(bool);

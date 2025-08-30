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

#include "callbacks.h"
#include "coverage.h"
#include "tracing.h"

void RegisterCallbackExports(Napi::Env env, Napi::Object exports) {
  exports["registerCoverageMap"] =
      Napi::Function::New<RegisterCoverageMap>(env);
  exports["registerNewCounters"] =
      Napi::Function::New<RegisterNewCounters>(env);
  exports["traceUnequalStrings"] =
      Napi::Function::New<TraceUnequalStrings>(env);
  exports["traceStringContainment"] =
      Napi::Function::New<TraceStringContainment>(env);
  exports["traceIntegerCompare"] =
      Napi::Function::New<TraceIntegerCompare>(env);
  exports["tracePcIndir"] = Napi::Function::New<TracePcIndir>(env);
}

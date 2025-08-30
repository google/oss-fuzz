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

#include <iostream>

#include "fuzzing_async.h"
#include "fuzzing_sync.h"

#include "shared/callbacks.h"

// A basic sanity check: ask the Node API for version information and print it.
void PrintVersion(const Napi::CallbackInfo &info) {
  auto napi_version = Napi::VersionManagement::GetNapiVersion(info.Env());
  auto node_version = Napi::VersionManagement::GetNodeVersion(info.Env());
  std::cout << "Jazzer.js running on Node " << node_version->major
            << " using Node-API version " << napi_version << std::endl;
}

// This code is defining a function called "Init" which is used to initialize a
// Node.js addon module. The function takes two arguments, an "env" object, and
// an "exports" object.
// The "exports" object is an instance of the `Napi::Object` class, which is
// used to define the exports of the Node.js addon module. The code is adding
// properties to the "exports" object, where each property is a JavaScript
// function that corresponds to a C++ function.
// `RegisterCallbackExports` links more functions needed, like coverage tracking
// capabilities.
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports["printVersion"] = Napi::Function::New<PrintVersion>(env);
  exports["startFuzzing"] = Napi::Function::New<StartFuzzing>(env);
  exports["startFuzzingAsync"] = Napi::Function::New<StartFuzzingAsync>(env);
  exports["stopFuzzingAsync"] = Napi::Function::New<StopFuzzingAsync>(env);
  exports["stopFuzzing"] = Napi::Function::New<StopFuzzing>(env);

  RegisterCallbackExports(env, exports);
  return exports;
}

// Macro that exports the "Init" function as the entry point of the addon module
// named "myPackage". When this addon is imported in a Node.js script, the
// "Init" function will be executed to define the exports of the addon.
// This effectively allows us to do this from the Node.js side of things:
// const jazzerjs = require('jazzerjs');
// jazzerjs.printVersion
NODE_API_MODULE(jazzerjs, Init)

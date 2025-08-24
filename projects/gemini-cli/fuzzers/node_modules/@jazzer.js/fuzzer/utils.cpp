// Copyright 2023 Code Intelligence GmbH
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

#include "utils.h"
#include "napi.h"
#include "shared/libfuzzer.h"
#include <csignal>
#include <iostream>

void StartLibFuzzer(const std::vector<std::string> &args,
                    fuzzer::UserCallback fuzzCallback) {
  std::vector<char *> fuzzer_arg_pointers;
  for (auto &arg : args)
    fuzzer_arg_pointers.push_back((char *)arg.data());

  int argc = fuzzer_arg_pointers.size();
  char **argv = fuzzer_arg_pointers.data();

  fuzzer::FuzzerDriver(&argc, &argv, fuzzCallback);
}

// Constructs a libfuzzer usable string array based on an array
// object originating from a `Napi::CallbackInfo` object that is
// pre-filled by the caller.
std::vector<std::string> LibFuzzerArgs(Napi::Env env,
                                       const Napi::Array &jsArgs) {
  std::vector<std::string> fuzzer_args;
  for (auto [_, fuzzer_arg] : jsArgs) {
    Napi::Value val = fuzzer_arg;
    if (!val.IsString()) {
      throw Napi::Error::New(env, "libfuzzer arguments have to be strings");
    }

    fuzzer_args.push_back(val.As<Napi::String>().Utf8Value());
  }
  return fuzzer_args;
}

// The following two small functions serve as a simple mechanism for keeping
// track of encountered return values in the fuzzed target function. IFF both
// `exclAsyncReturns` and `exclSyncReturns` are toggled the `mixedReturns` is
// enabled. These toggles are used to inform the user about a potential
// performance benefit when fuzzing asynchronously but only synchronous return
// values are observed during a campaign. In such cases a user will be informed
// about this once libfuzzer exits, e.g. due to a crash, or timeout.
bool exclSyncReturns = false, exclAsyncReturns = false, mixedReturns = false;
void AsyncReturnsHandler() {
  exclAsyncReturns = true;
  if (exclSyncReturns) {
    mixedReturns = true;
  }
}

void SyncReturnsHandler() {
  exclSyncReturns = true;
  if (exclAsyncReturns) {
    mixedReturns = true;
  }
}

void ReturnValueInfo(bool is_sync_runner) {
  if (!is_sync_runner) {
    if (exclSyncReturns && !mixedReturns) {
      std::cerr
          << "\n== Jazzer.js:\n"
          << "  Exclusively observed synchronous return values from fuzzed "
             "function."
          << " Fuzzing in synchronous mode seems beneficial!\n"
          << "  To enable it, append a `--sync` to your Jazzer.js invocation."
          << std::endl;
    }
  } else {
    if (mixedReturns) {
      std::cerr << "\n== Jazzer.js:\n"
                << "  Observed asynchronous return values from "
                   "fuzzed function."
                << " Fuzzing in asynchronous mode seems beneficial!\n"
                << "  Remove the `--sync` flag from your Jazzer.js invocation."
                << std::endl;
    }
  }
}

int StopFuzzingHandleExit(const Napi::CallbackInfo &info) {
  int exitCode = libfuzzer::ExitErrorCode;

  if (info[0].IsNumber()) {
    exitCode = info[0].As<Napi::Number>().Int32Value();

    if (exitCode == SIGSEGV) {
      libfuzzer::PrintCrashingInput();
    }
  } else {
    // If a dedicated status code is provided, the run is executed as internal
    // test and the crashing input does not need to be printed/saved.
    libfuzzer::PrintCrashingInput();
  }
  return exitCode;
}

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

#include "fuzzing_sync.h"
#include "shared/libfuzzer.h"
#include "utils.h"
#include <csignal>
#include <cstdlib>
#include <optional>

namespace {
// Information about a JS fuzz target.
struct FuzzTargetInfo {
  Napi::Env env;
  Napi::Function target;
  Napi::Function jsStopCallback; // JS stop function used by signal handling.
};

// The JS fuzz target. We need to store the function pointer in a global
// variable because libfuzzer doesn't give us a way to feed user-provided data
// to its target function.
std::optional<FuzzTargetInfo> gFuzzTarget;

// Track if SIGINT signal handler was called.
// This is only necessary in the sync fuzzing case, as async can be handled
// much nicer directly in JavaScript.
volatile std::sig_atomic_t gSignalStatus;
} // namespace

void sigintHandler(int signum) { gSignalStatus = signum; }

// The libFuzzer callback when fuzzing synchronously
int FuzzCallbackSync(const uint8_t *Data, size_t Size) {
  // Create a new active scope so that handles for the buffer objects created in
  // this function will be associated with it. This makes sure that these
  // handles are only held live through the lifespan of this scope and gives
  // the garbage collector a chance to deallocate them between the fuzzer
  // iterations. Otherwise, new handles will be associated with the original
  // scope created by Node.js when calling StartFuzzing. The lifespan for this
  // default scope is tied to the lifespan of the native method call. The result
  // is that, by default, handles remain valid and the objects associated with
  // these handles will be held live for the lifespan of the native method call.
  // This would exhaust memory resources since we run in an endless fuzzing loop
  // and only return when a bug is found. See:
  // https://github.com/nodejs/node-addon-api/blob/35b65712c26a49285cdbe2b4d04e25a5eccbe719/doc/object_lifetime_management.md
  auto scope = Napi::HandleScope(gFuzzTarget->env);

  // TODO Do we really want to copy the data? The user isn't allowed to
  // modify it (else the fuzzer will abort); moreover, we don't know when
  // the JS buffer is going to be garbage-collected. But it would still be
  // nice for efficiency if we could use a pointer instead of copying.
  //
  auto data = Napi::Buffer<uint8_t>::Copy(gFuzzTarget->env, Data, Size);
  auto result = gFuzzTarget->target.Call({data});

  if (result.IsPromise()) {
    AsyncReturnsHandler();
  } else {
    SyncReturnsHandler();
  }

  if (gSignalStatus != 0) {
    // Non-zero exit codes will produce crash files.
    auto exitCode = Napi::Number::New(gFuzzTarget->env, 0);

    if (gSignalStatus != SIGINT) {
      exitCode = Napi::Number::New(gFuzzTarget->env, gSignalStatus);
    }

    // Execute the signal handler in context of the node application.
    gFuzzTarget->jsStopCallback.Call({exitCode});
  }

  return EXIT_SUCCESS;
}

// Start libfuzzer with a JS fuzz target.
//
// This is a JS-enabled version of libfuzzer's main function (see
// FuzzerMain.cpp in the compiler-rt source). It takes the fuzz target, which
// must be a JS function taking a single data argument, as its first
// parameter; the fuzz target's return value is ignored. The second argument
// is an array of (command-line) arguments to pass to libfuzzer.
void StartFuzzing(const Napi::CallbackInfo &info) {
  if (info.Length() != 3 || !info[0].IsFunction() || !info[1].IsArray() ||
      !info[2].IsFunction()) {
    throw Napi::Error::New(
        info.Env(),
        "Need three arguments, which must be the fuzz target "
        "function, an array of libfuzzer arguments, and a callback function "
        "that the fuzzer will call in case of SIGINT or a segmentation fault");
  }

  auto fuzzer_args = LibFuzzerArgs(info.Env(), info[1].As<Napi::Array>());

  // Store the JS fuzz target and corresponding environment globally, so that
  // our C++ fuzz target can use them to call back into JS. Also store the stop
  // function that will be called in case of a SIGINT/SIGSEGV.
  gFuzzTarget = {info.Env(), info[0].As<Napi::Function>(),
                 info[2].As<Napi::Function>()};

  signal(SIGINT, sigintHandler);
  signal(SIGSEGV, sigintHandler);

  StartLibFuzzer(fuzzer_args, FuzzCallbackSync);
  // Explicitly reset the global function pointer because the JS
  // function reference that it's currently holding will become invalid
  // when we return.
  gFuzzTarget = {};
}

void StopFuzzing(const Napi::CallbackInfo &info) {
  int exitCode = StopFuzzingHandleExit(info);

  // If we ran in async mode, and we only ever encountered synchronous results
  // we'll give an indicator that running in synchronous mode is likely
  // beneficial.
  ReturnValueInfo(true);

  // We call _Exit to immediately terminate the process without performing any
  // cleanup including libfuzzer exit handlers. These handlers print information
  // about the native libfuzzer target which is neither relevant nor actionable
  // for JavaScript developers. We provide the relevant crash information
  // such as the error message and stack trace in Jazzer.js CLI.
  _Exit(exitCode);
}

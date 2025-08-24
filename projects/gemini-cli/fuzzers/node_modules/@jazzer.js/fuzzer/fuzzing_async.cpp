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

#include "napi.h"
#include <cstdlib>
#include <future>
#include <iostream>

#ifdef _WIN32
#include <process.h>
#define GetPID _getpid
#else
#include <unistd.h>
#define GetPID getpid
#endif

#include "fuzzing_async.h"
#include "shared/libfuzzer.h"
#include "utils.h"

namespace {

// The context of the typed thread-safe function we use to call the JavaScript
// fuzz target.
struct AsyncFuzzTargetContext {
  explicit AsyncFuzzTargetContext(Napi::Env env)
      : deferred(Napi::Promise::Deferred::New(env)){};
  std::thread native_thread;
  Napi::Promise::Deferred deferred;
  bool is_resolved = false;
  bool is_done_called = false;
  bool is_data_resolved = false;
  AsyncFuzzTargetContext() = delete;
};

// The data type to use each time we schedule a call to the JavaScript fuzz
// target. It includes the fuzzer-generated input and a promise to wait for the
// promise returned by the fuzz target to be resolved or rejected.
struct DataType {
  const uint8_t *data;
  size_t size;
  std::promise<void *> *promise;

  DataType() = delete;
};

// Exception for catching crashes in the JavaScript callback function.
class JSException : public std::exception {};

void CallJsFuzzCallback(Napi::Env env, Napi::Function jsFuzzCallback,
                        AsyncFuzzTargetContext *context, DataType *data);
using TSFN = Napi::TypedThreadSafeFunction<AsyncFuzzTargetContext, DataType,
                                           CallJsFuzzCallback>;
using FinalizerDataType = void;

TSFN gTSFN;

// The libFuzzer callback when fuzzing asynchronously.
int FuzzCallbackAsync(const uint8_t *Data, size_t Size) {
  std::promise<void *> promise;
  auto input = DataType{Data, Size, &promise};

  auto future = promise.get_future();
  auto status = gTSFN.BlockingCall(&input);
  if (status != napi_ok) {
    Napi::Error::Fatal(
        "FuzzCallbackAsync",
        "Napi::TypedThreadSafeNapi::Function.BlockingCall() failed");
  }
  // Wait until the JavaScript fuzz target has finished.
  try {
    future.get();
  } catch (JSException &exception) {
    throw;
  } catch (std::exception &exception) {
    std::cerr << "==" << (unsigned long)GetPID()
              << "== Jazzer.js: unexpected Error: " << exception.what()
              << std::endl;
    libfuzzer::PrintCrashingInput();
    // We call exit to immediately terminates the process without performing any
    // cleanup including libfuzzer exit handlers.
    _Exit(libfuzzer::ExitErrorCode);
  }
  return EXIT_SUCCESS;
}

// This function is the callback that gets executed in the addon's main thread
// (i.e., the JavaScript event loop thread) and thus we can call the JavaScript
// code and use the Node API to create JavaScript objects.
void CallJsFuzzCallback(Napi::Env env, Napi::Function jsFuzzCallback,
                        AsyncFuzzTargetContext *context, DataType *data) {
  // Execute the fuzz target and reject the deferred on any raised exception by
  // C++ code or returned error by JS interop to stop fuzzing. Any exception
  // thrown from this function would cause a process termination. If the fuzz
  // target is executed successfully resolve data->promise to unblock the fuzzer
  // thread and continue with the next invocation.

  try {
    if (env != nullptr) {
      auto buffer = Napi::Buffer<uint8_t>::Copy(env, data->data, data->size);

      auto parameterCount = jsFuzzCallback.As<Napi::Object>()
                                .Get("length")
                                .As<Napi::Number>()
                                .Int32Value();
      // In case more than one parameter is expected, the second one is
      // considered to be a done callback to indicate finished execution.
      if (parameterCount > 1) {
        context->is_done_called = false;
        context->is_data_resolved = false;
        context->is_resolved = false;
        auto done =
            Napi::Function::New<>(env, [=](const Napi::CallbackInfo &info) {
              // If the done callback based fuzz target also returned a promise,
              // is_resolved could been set and there's nothing to do anymore.
              // As the done callback is executed on the main event loop, no
              // synchronization for is_resolved is needed.
              if (context->is_resolved) {
                return;
              }

              // Raise an error if the done callback is called multiple times.
              if (context->is_done_called) {
                context->deferred.Reject(
                    Napi::Error::New(env, "Expected done to be called once, "
                                          "but it was called multiple times.")
                        .Value());
                context->is_resolved = true;
                // We can not pass an exception in data->promise to break out of
                // the fuzzer loop, as it was already resolved in the last
                // invocation of the done callback. Probably the best thing to
                // do is print an error message and await the timeout.
                std::cerr << "Expected done to be called once, but it was "
                             "called multiple times."
                          << std::endl;
                return;
              }

              // Mark if the done callback is invoked, to be able to check for
              // wrongly returned promises and multiple invocations.
              context->is_done_called = true;

              auto hasError = !(info[0].IsNull() || info[0].IsUndefined());
              if (hasError) {
                context->deferred.Reject(info[0].As<Napi::Error>().Value());
                context->is_resolved = true;
                data->promise->set_exception(
                    std::make_exception_ptr(JSException()));
              } else {
                data->promise->set_value(nullptr);
              }
            });
        auto result = jsFuzzCallback.Call({buffer, done});
        context->is_data_resolved = true;
        if (result.IsPromise()) {
          // If the fuzz target received a done callback, but also returned a
          // promise, the callback could already have been called. In that case
          // is_done_called is already set. If is_resolved is also set, the
          // callback was invoked with an error and already propagated that. If
          // not, an appropriate error, describing the illegal return value,
          // can be set. As everything is executed on the main event loop, no
          // synchronization is needed.
          AsyncReturnsHandler();
          if (context->is_resolved) {
            return;
          }
          if (!context->is_done_called) {
            data->promise->set_exception(
                std::make_exception_ptr(JSException()));
          }
          context->deferred.Reject(
              Napi::Error::New(env, "Internal fuzzer error - Either async or "
                                    "done callback based fuzz tests allowed.")
                  .Value());
          context->is_resolved = true;
        } else {
          SyncReturnsHandler();
        }
        return;
      }

      auto result = jsFuzzCallback.Call({buffer});

      // Register callbacks on returned promise to await its resolution before
      // resolving the fuzzer promise and continue fuzzing. Otherwise, resolve
      // and continue directly.
      if (result.IsPromise()) {
        AsyncReturnsHandler();
        auto jsPromise = result.As<Napi::Object>();
        auto then = jsPromise.Get("then").As<Napi::Function>();
        then.Call(
            jsPromise,
            {Napi::Function::New<>(env,
                                   [=](const Napi::CallbackInfo &info) {
                                     data->promise->set_value(nullptr);
                                   }),
             Napi::Function::New<>(env, [=](const Napi::CallbackInfo &info) {
               // This is the only way to pass an exception from JavaScript
               // through C++ back to calling JavaScript code.
               context->deferred.Reject(info[0].As<Napi::Error>().Value());
               context->is_resolved = true;
               data->promise->set_exception(
                   std::make_exception_ptr(JSException()));
             })});
      } else {
        SyncReturnsHandler();
        data->promise->set_value(nullptr);
      }
    } else {
      data->promise->set_exception(std::make_exception_ptr(
          std::runtime_error("Environment is shut down")));
    }
  } catch (const Napi::Error &error) {
    if (context->is_resolved)
      return;
    context->deferred.Reject(error.Value());
    context->is_resolved = true;
    data->promise->set_exception(std::make_exception_ptr(JSException()));
  } catch (const std::exception &exception) {
    auto message =
        std::string("Internal fuzzer error - ").append(exception.what());
    context->deferred.Reject(Napi::Error::New(env, message).Value());
    context->is_resolved = true;
    data->promise->set_exception(std::make_exception_ptr(JSException()));
  }
}

} // namespace

// Start libfuzzer with a JS fuzz target asynchronously.
//
// This is a JS-enabled version of libfuzzer's main function (see FuzzerMain.cpp
// in the compiler-rt source). It takes the fuzz target, which must be a JS
// function taking a single data argument, as its first parameter; the fuzz
// target's return value is ignored. The second argument is an array of
// (command-line) arguments to pass to libfuzzer.
//
// In order not to block JavaScript event loop, we start libfuzzer in a separate
// thread and use a typed thread-safe function to manage calls to the JavaScript
// fuzz target which can only happen in the addon's main thread. This function
// returns a promise so that the JavaScript code can use `catch()` to check when
// the promise is rejected.
Napi::Value StartFuzzingAsync(const Napi::CallbackInfo &info) {
  if (info.Length() != 2 || !info[0].IsFunction() || !info[1].IsArray()) {
    throw Napi::Error::New(info.Env(),
                           "Need two arguments, which must be the fuzz target "
                           "function and an array of libfuzzer arguments");
  }

  auto fuzzer_args = LibFuzzerArgs(info.Env(), info[1].As<Napi::Array>());

  // Store the JS fuzz target and corresponding environment, so that our C++
  // fuzz target can use them to call back into JS.
  auto *context = new AsyncFuzzTargetContext(info.Env());

  gTSFN = TSFN::New(
      info.Env(),
      info[0]
          .As<Napi::Function>(), // JavaScript fuzz target called asynchronously
      "FuzzerAsyncAddon",
      0,       // Unlimited Queue
      1,       // Only one thread will use this initially
      context, // context
      [](Napi::Env env, FinalizerDataType *, AsyncFuzzTargetContext *ctx) {
        // This finalizer is executed in the main event loop context and hence
        // has access to the JavaScript environment. It's only invoked if no
        // issue was found.
        ctx->native_thread.join();
        if (!ctx->is_resolved) {
          ctx->deferred.Resolve(Napi::Boolean::New(env, true));
        }
        delete ctx;
      });

  // Start the libFuzzer loop in a separate thread in order not to block the
  // JavaScript event loop.
  context->native_thread = std::thread(
      [](std::vector<std::string> fuzzer_args, AsyncFuzzTargetContext *ctx) {
        try {
          StartLibFuzzer(fuzzer_args, FuzzCallbackAsync);
        } catch (const JSException &exception) {
        }
        gTSFN.Release();
      },
      std::move(fuzzer_args), context);

  return context->deferred.Promise();
}

void StopFuzzingAsync(const Napi::CallbackInfo &info) {
  int exitCode = StopFuzzingHandleExit(info);

  // If we ran in async mode and we only ever encountered synchronous results
  // we'll give an indicator that running in synchronous mode is likely
  // benefical
  ReturnValueInfo(false);

  // We call _Exit to immediately terminate the process without performing any
  // cleanup including libfuzzer exit handlers. These handlers print information
  // about the native libfuzzer target which is neither relevant nor actionable
  // for JavaScript developers. We provide the relevant crash information
  // such as the error message and stack trace in Jazzer.js CLI.
  _Exit(exitCode);
}

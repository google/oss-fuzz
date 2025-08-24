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

#include "tracing.h"

// We expect these symbols to exist in the current plugin, provided either by
// libfuzzer or by the native agent.
extern "C" {
void __sanitizer_weak_hook_strcmp(void *called_pc, const char *s1,
                                  const char *s2, int result);
void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1,
                                  const char *s2, const char *result);
void __sanitizer_cov_trace_const_cmp8_with_pc(uintptr_t called_pc,
                                              uint64_t arg1, uint64_t arg2);
void __sanitizer_cov_trace_pc_indir_with_pc(void *caller_pc, uintptr_t callee);
}

// Record a comparison between two strings in the target that returned unequal.
void TraceUnequalStrings(const Napi::CallbackInfo &info) {
  if (info.Length() != 3) {
    throw Napi::Error::New(info.Env(),
                           "Need three arguments: the trace ID and the two "
                           "compared strings");
  }

  auto id = info[0].As<Napi::Number>().Int64Value();
  auto s1 = info[1].As<Napi::String>().Utf8Value();
  auto s2 = info[2].As<Napi::String>().Utf8Value();

  // strcmp returns zero on equality, and libfuzzer doesn't care about the
  // result beyond whether it's zero or not.
  __sanitizer_weak_hook_strcmp((void *)id, s1.c_str(), s2.c_str(), 1);
}

// Record a substring check to find the first occurrence of the byte string
// needle in the byte string pointed to by haystack
void TraceStringContainment(const Napi::CallbackInfo &info) {
  if (info.Length() != 3) {
    throw Napi::Error::New(
        info.Env(), "Need three arguments: the trace ID and the two strings");
  }

  auto id = info[0].As<Napi::Number>().Int64Value();
  auto needle = info[1].As<Napi::String>().Utf8Value();
  auto haystack = info[2].As<Napi::String>().Utf8Value();

  // libFuzzer currently ignores the result, which allows us to simply pass a
  // valid but arbitrary pointer here instead of performing an actual strstr
  // operation.
  __sanitizer_weak_hook_strstr((void *)id, needle.c_str(), haystack.c_str(),
                               needle.c_str());
}

void TraceIntegerCompare(const Napi::CallbackInfo &info) {
  if (info.Length() != 3) {
    throw Napi::Error::New(
        info.Env(),
        "Need three arguments: the trace ID and the two compared numbers");
  }

  auto id = info[0].As<Napi::Number>().Int64Value();
  auto arg1 = info[1].As<Napi::Number>().Int64Value();
  auto arg2 = info[2].As<Napi::Number>().Int64Value();
  __sanitizer_cov_trace_const_cmp8_with_pc(id, arg1, arg2);
}

void TracePcIndir(const Napi::CallbackInfo &info) {
  if (info.Length() != 2) {
    throw Napi::Error::New(info.Env(),
                           "Need two arguments: the PC value & the trace ID");
  }

  auto id = info[0].As<Napi::Number>().Int64Value();
  auto state = info[1].As<Napi::Number>().Int64Value();
  __sanitizer_cov_trace_pc_indir_with_pc((void *)id, state);
}

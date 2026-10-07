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

#pragma once
#include <cstring>
#include "v8.h"

namespace fuzz::precompiled {

// Compile `src` once into a Function and cache it in `cache`.
inline bool EnsureFn(v8::Isolate* iso,
                     v8::Local<v8::Context> ctx,
                     const char* src,
                     v8::Global<v8::Function>& cache) {
  if (!cache.IsEmpty()) return true;
  v8::Local<v8::String> s;
  if (!v8::String::NewFromUtf8(iso, src, v8::NewStringType::kNormal).ToLocal(&s)) return false;
  v8::Local<v8::Script> script;
  if (!v8::Script::Compile(ctx, s).ToLocal(&script)) return false;
  v8::Local<v8::Value> fn;
  if (!script->Run(ctx).ToLocal(&fn)) return false;
  cache.Reset(iso, fn.As<v8::Function>());
  return true;
}

// Call a function and ignore exceptions/return values.
inline void CallNoThrow(v8::Isolate* iso,
                        v8::Local<v8::Context> ctx,
                        v8::Local<v8::Function> fn,
                        int argc,
                        v8::Local<v8::Value>* argv) {
  v8::TryCatch tc(iso);
  (void)fn->Call(ctx, v8::Undefined(iso), argc, argv);
}

// Create an ArrayBuffer and copy bytes into it.
inline v8::Local<v8::ArrayBuffer> CopyToArrayBuffer(v8::Isolate* iso,
                                                    const void* data,
                                                    size_t len) {
  v8::Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(iso, len);
  if (len) std::memcpy(ab->GetBackingStore()->Data(), data, len);
  return ab;
}

// Create a V8 UTF-8 string from std::string.
inline bool NewUtf8String(v8::Isolate* iso,
                          const std::string& s,
                          v8::Local<v8::String>* out) {
  return v8::String::NewFromUtf8(iso, s.c_str(),
                                 v8::NewStringType::kNormal,
                                 static_cast<int>(s.size())).ToLocal(out);
}

} // namespace fuzz::precompiled

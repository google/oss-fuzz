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

/*
 * A fuzzer focused on C string -> Javascript String using N-API.
 * Extended to cover UTF-16, external strings, optimized property keys,
 * length-query getter paths, napi_coerce_to_string, and exception draining.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "js_native_api.h"
#include "js_native_api_v8.h"
#include "node.h"
#include "node_internals.h"
#include "node_api_internals.h"
#include "env-inl.h"
#include "util-inl.h"
#include "v8.h"

#include "fuzz_common.h"  // IsolateScope + RunInEnvironment

// --- Helpers ---------------------------------------------------------------

// Drain (and ignore) any pending exception on the env to avoid fatal V8 scopes
static inline void DrainLastException(napi_env env) {
  if (!env) return;
  bool pending = false;
  if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
    napi_value exc = nullptr;
    (void)napi_get_and_clear_last_exception(env, &exc);
  }
}

// Optional: same deleter you had (used for external strings)
static void free_string(node_api_nogc_env /*env*/, void* data, void* /*hint*/) {
  std::free(data);
}

// Static used only to receive env from addon init; reset every run.
static napi_env g_addon_env = nullptr;

// Non-capturing addon init to receive napi_env
static napi_value CaptureEnvInit(napi_env env, napi_value exports) {
  g_addon_env = env;
  return exports;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* bytes = reinterpret_cast<const char*>(data);
  std::string s(bytes, size);

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;

  // Fresh Context + Environment for this input
  fuzz::RunInEnvironment(iso.isolate(),
    [&](node::Environment* /*env*/, v8::Local<v8::Context> context) {
      g_addon_env = nullptr;  // reset before registering

      // Create module/exports objects and register a dummy addon to obtain napi_env.
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      v8::Local<v8::Object> module_obj  = v8::Object::New(isolate);
      v8::Local<v8::Object> exports_obj = v8::Object::New(isolate);

      napi_module_register_by_symbol(
          exports_obj, module_obj, context, &CaptureEnvInit, NAPI_VERSION);

      napi_env addon_env = g_addon_env;
      if (addon_env == nullptr) {
        // Couldn’t get an env; bail out gracefully.
        return;
      }

      // ---- Original N-API string ops (augmented below) ----
      size_t copied1 = 0, copied2 = 0;
      bool copied3 = false;
      napi_value output1{}, output2{}, output3{}, output4{}, output5{}, output6{},
                 output7{}, output8{}, output9{}, output10{}, output11{},
                 output12{};

      // Allocate temp buffers (respecting size)
      char* buf1 = static_cast<char*>(std::malloc(size ? size : 1));
      char* buf2 = static_cast<char*>(std::malloc(size ? size : 1));
      if (!buf1 || !buf2) {
        std::free(buf1); std::free(buf2);
        return;
      }

      // create/get UTF-8
      (void) napi_create_string_utf8(addon_env, s.data(), size, &output1);
      DrainLastException(addon_env);
      (void) napi_get_value_string_utf8(addon_env, output1, buf1, size, &copied1);
      DrainLastException(addon_env);

      // create/get Latin-1
      (void) napi_create_string_latin1(addon_env, s.data(), size, &output2);
      DrainLastException(addon_env);
      (void) napi_get_value_string_latin1(addon_env, output2, buf2, size, &copied2);
      DrainLastException(addon_env);

      // symbol.for
      (void) node_api_symbol_for(addon_env, s.data(), size, &output4);
      DrainLastException(addon_env);

      // Property ops using raw fuzz bytes for the property name
      (void) napi_set_named_property(addon_env, output1, s.c_str(), output2);
      DrainLastException(addon_env);
      (void) napi_get_named_property(addon_env, output1, s.c_str(), &output6);
      DrainLastException(addon_env);
      (void) napi_has_named_property(addon_env, output1, s.c_str(), &copied3);
      DrainLastException(addon_env);

      (void) napi_get_property_names(addon_env, output1, &output7);
      DrainLastException(addon_env);
      (void) napi_has_property(addon_env, output1, output2, &copied3);
      DrainLastException(addon_env);
      (void) napi_get_property(addon_env, output1, output2, &output8);
      DrainLastException(addon_env);
      (void) napi_delete_property(addon_env, output1, output2, &copied3);
      DrainLastException(addon_env);
      (void) napi_has_own_property(addon_env, output1, output2, &copied3);
      DrainLastException(addon_env);

      (void) napi_create_type_error(addon_env, output1, output2, &output9);
      DrainLastException(addon_env);
      (void) napi_create_range_error(addon_env, output1, output2, &output10);
      DrainLastException(addon_env);
      (void) node_api_create_syntax_error(addon_env, output1, output2, &output11);
      DrainLastException(addon_env);

      (void) napi_run_script(addon_env, output2, &output12);
      DrainLastException(addon_env);

      // -----------------------------------------------------------------
      // Length-query getter paths for UTF-8 / Latin-1
      size_t needed_utf8 = 0;
      (void) napi_get_value_string_utf8(addon_env, output1, nullptr, 0, &needed_utf8);
      DrainLastException(addon_env);
      if (needed_utf8 > 0 && needed_utf8 < (1ull << 20)) { // cap alloc
        char* dyn_utf8 = static_cast<char*>(std::malloc(needed_utf8 + 1));
        if (dyn_utf8) {
          size_t got = 0;
          (void) napi_get_value_string_utf8(addon_env, output1, dyn_utf8, needed_utf8 + 1, &got);
          DrainLastException(addon_env);
          std::free(dyn_utf8);
        }
      }

      size_t needed_latin1 = 0;
      (void) napi_get_value_string_latin1(addon_env, output2, nullptr, 0, &needed_latin1);
      DrainLastException(addon_env);
      if (needed_latin1 > 0 && needed_latin1 < (1ull << 20)) {
        char* dyn_latin1 = static_cast<char*>(std::malloc(needed_latin1 + 1));
        if (dyn_latin1) {
          size_t got = 0;
          (void) napi_get_value_string_latin1(addon_env, output2, dyn_latin1, needed_latin1 + 1, &got);
          DrainLastException(addon_env);
          std::free(dyn_latin1);
        }
      }

      // UTF-16 create/get and length-query path
      // Build a UTF-16LE buffer from fuzz bytes (pair up bytes; if odd, drop last byte)
      size_t u16_len = size / 2;
      if (u16_len == 0) u16_len = 1; // ensure non-zero for coverage
      char16_t* u16_in = static_cast<char16_t*>(std::malloc(sizeof(char16_t) * u16_len));
      if (u16_in) {
        for (size_t i = 0; i < u16_len; ++i) {
          uint16_t lo = (2*i < size) ? static_cast<uint8_t>(data[2*i]) : 0;
          uint16_t hi = (2*i + 1 < size) ? static_cast<uint8_t>(data[2*i + 1]) : 0;
          u16_in[i] = static_cast<char16_t>((hi << 8) | lo);
        }
        napi_value out_u16{};
        (void) napi_create_string_utf16(addon_env, u16_in, u16_len, &out_u16);
        DrainLastException(addon_env);

        // Length query first
        size_t needed_u16 = 0;
        (void) napi_get_value_string_utf16(addon_env, out_u16, nullptr, 0, &needed_u16);
        DrainLastException(addon_env);

        // Then allocate and fetch
        if (needed_u16 == 0) needed_u16 = 1;
        char16_t* u16_out = static_cast<char16_t*>(std::malloc(sizeof(char16_t) * (needed_u16 + 1)));
        if (u16_out) {
          size_t got_u16 = 0;
          (void) napi_get_value_string_utf16(addon_env, out_u16, u16_out, needed_u16 + 1, &got_u16);
          DrainLastException(addon_env);
          std::free(u16_out);
        }

        // Use the UTF-16 string in property ops too
        (void) napi_set_property(addon_env, out_u16, output2 /*key string*/, out_u16);
        (void) napi_has_property(addon_env, out_u16, output2, &copied3);
        DrainLastException(addon_env);

        std::free(u16_in);
      }

      // Optimized property-key creators (UTF-8 / Latin-1 / UTF-16)
      napi_value key_u8{}, key_l1{}, key_u16{};
      (void) node_api_create_property_key_utf8(addon_env, s.data(), size, &key_u8);
      (void) node_api_create_property_key_latin1(addon_env, s.data(), size, &key_l1);
      DrainLastException(addon_env);

      // Build a short u16 key buffer (re-use first few code units of previous conversion)
      size_t key16_len = (size / 2) ? (size / 2) : 1;
      char16_t* key16_buf = static_cast<char16_t*>(std::malloc(sizeof(char16_t) * key16_len));
      if (key16_buf) {
        for (size_t i = 0; i < key16_len; ++i) {
          uint16_t lo = (2*i < size) ? static_cast<uint8_t>(data[2*i]) : 0;
          uint16_t hi = (2*i + 1 < size) ? static_cast<uint8_t>(data[2*i + 1]) : 0;
          key16_buf[i] = static_cast<char16_t>((hi << 8) | lo);
        }
        (void) node_api_create_property_key_utf16(addon_env, key16_buf, key16_len, &key_u16);
        DrainLastException(addon_env);
      }

      // Try using these keys on a string receiver (boxed in JS)
      if (key_u8)  {
        napi_value tmp{};
        (void) napi_set_property(addon_env, output1, key_u8, output2);
        DrainLastException(addon_env);
        (void) napi_get_property(addon_env, output1, key_u8, &tmp);
        DrainLastException(addon_env);
      }
      if (key_l1)  {
        napi_value tmp{};
        (void) napi_set_property(addon_env, output1, key_l1, output1);
        DrainLastException(addon_env);
        (void) napi_get_property(addon_env, output1, key_l1, &tmp);
        DrainLastException(addon_env);
      }
      if (key_u16) {
        napi_value tmp{};
        (void) napi_set_property(addon_env, output1, key_u16, output4);
        DrainLastException(addon_env);
        (void) napi_get_property(addon_env, output1, key_u16, &tmp);
        DrainLastException(addon_env);
      }

      std::free(key16_buf);

      // External strings (Latin-1 and UTF-16) with finalizers.
      // For external-string APIs: if 'copied' comes back true, free immediately
      // (engine made a copy and will NOT call the finalizer). If false, the GC
      // will call 'free_string' later, so don't free here.

      // External Latin-1
      {
        bool copied = false;
        size_t ext_len = size ? size : 1;
        char* ext_l1 = static_cast<char*>(std::malloc(ext_len));
        if (ext_l1) {
          if (size) {
            std::memcpy(ext_l1, s.data(), size);
          } else {
            ext_l1[0] = '\0';  // deterministic content when input is empty
          }

          napi_value ext_l1_val{};
          (void) node_api_create_external_string_latin1(
              addon_env, ext_l1, ext_len, free_string, nullptr, &ext_l1_val, &copied);
          DrainLastException(addon_env);

          // Touch it a bit
          (void) napi_coerce_to_string(addon_env, ext_l1_val, &output3);
          (void) napi_has_property(addon_env, ext_l1_val, key_u8 ? key_u8 : output2, &copied3);
          DrainLastException(addon_env);

          if (copied) {
            // Engine copied data; finalizer won't run. Free now.
            std::free(ext_l1);
          }
        }
      }

      // External UTF-16
      {
        bool copied_ext16 = false;
        size_t ext16_len = (size / 2) ? (size / 2) : 1;
        char16_t* ext_u16 = static_cast<char16_t*>(std::malloc(sizeof(char16_t) * ext16_len));
        if (ext_u16) {
          for (size_t i = 0; i < ext16_len; ++i) {
            uint16_t lo = (2*i < size) ? static_cast<uint8_t>(data[2*i]) : 0;
            uint16_t hi = (2*i + 1 < size) ? static_cast<uint8_t>(data[2*i + 1]) : 0;
            ext_u16[i] = static_cast<char16_t>((hi << 8) | lo);
          }

          napi_value ext_u16_val{};
          (void) node_api_create_external_string_utf16(
              addon_env, ext_u16, ext16_len, free_string, nullptr, &ext_u16_val, &copied_ext16);
          DrainLastException(addon_env);

          // Exercise getter path on it
          size_t need16 = 0;
          (void) napi_get_value_string_utf16(addon_env, ext_u16_val, nullptr, 0, &need16);
          DrainLastException(addon_env);
          if (need16 == 0) need16 = 1;
          char16_t* tmp16 = static_cast<char16_t*>(std::malloc(sizeof(char16_t) * (need16 + 1)));
          if (tmp16) {
            size_t got16 = 0;
            (void) napi_get_value_string_utf16(addon_env, ext_u16_val, tmp16, need16 + 1, &got16);
            DrainLastException(addon_env);
            std::free(tmp16);
          }

          if (copied_ext16) {
            std::free(ext_u16);
          }
        }
      }

      {
        napi_value coerced{};
        (void) napi_coerce_to_string(addon_env, output4 /* Symbol.for(...) */, &coerced);
        (void) napi_coerce_to_string(addon_env, output7 /* property names array */, &coerced);
        (void) napi_coerce_to_string(addon_env, output9 /* TypeError object */, &coerced);
        (void) napi_coerce_to_string(addon_env, output12 /* result of run_script */, &coerced);
        DrainLastException(addon_env);
      }

      // Clean up original temp buffers
      std::free(buf1);
      std::free(buf2);

      // Final safeguard: ensure no exception is left pending before we return.
      DrainLastException(addon_env);
      g_addon_env = nullptr;  // avoid leakage across inputs
    },
    /*opts=*/fuzz::EnvRunOptions{
        node::EnvironmentFlags::kDefaultFlags,
        /*print_js_to_stdout=*/false,
        /*max_pumps=*/4  // give microtasks/callbacks a chance, still bounded
    });

  return 0;
}

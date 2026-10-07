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

#include "fuzz_common.h"

#include <cstdlib>
#include <string>
#include <vector>

#include "uv.h"
#include "v8.h"

#include "node.h"
#include "node_platform.h"
#include "env-inl.h"
#include "util-inl.h"

// cppgc platform init/shutdown like cctest does
#include "cppgc/platform.h"

#if defined(__GLIBC__)
#include <malloc.h>  // malloc_trim
#endif

namespace fuzz {
namespace {

// -------- Process-wide, persistent Node/V8 state (single Environment) --------
std::unique_ptr<node::NodePlatform> g_platform;
uv_loop_t                            g_persist_loop;

using ABAUnique =
    std::unique_ptr<node::ArrayBufferAllocator, decltype(&node::FreeArrayBufferAllocator)>;

ABAUnique                            g_persist_allocator{ nullptr, &node::FreeArrayBufferAllocator };

v8::Isolate*                         g_iso = nullptr;
v8::Global<v8::Context>              g_ctx;
node::IsolateData*                   g_iso_data = nullptr;
node::Environment*                   g_env = nullptr;

// Pre-compiled JS function: (a:ArrayBuffer, b:ArrayBuffer) => Buffer.compare(...)
v8::Global<v8::Function>             g_bufcmp_fn;

// Helper: run platform tasks + libuv + microtasks once.
// Returns true if any progress was made.
// NOTE: Callers must have entered the isolate (Isolate::Scope) before calling.
static inline bool OnePump(v8::Isolate* isolate,
                           node::NodePlatform* platform,
                           uv_loop_t* loop) {
  bool progressed = false;
  platform->DrainTasks(isolate);
  progressed |= (uv_run(loop, UV_RUN_NOWAIT) != 0);
  isolate->PerformMicrotaskCheckpoint();
  return progressed;
}

// Drain up to max_spins or until the loop is idle.
// Enters the isolate to satisfy V8 invariants while touching microtasks/heap.
static inline void DrainUntilIdle(v8::Isolate* isolate,
                                  node::NodePlatform* platform,
                                  uv_loop_t* loop,
                                  int max_spins = 256) {
  v8::Isolate::Scope iso_scope(isolate);
  v8::HandleScope hs(isolate);
  for (int i = 0; i < max_spins; ++i) {
    const bool progressed = OnePump(isolate, platform, loop);
    if (!progressed && !uv_loop_alive(loop)) break;
  }
}

// Build (once) a comparator that DOES NOT copy: Buffer.from(ArrayBuffer) shares memory.
static void BuildBufCmpOnce() {
  if (!g_bufcmp_fn.IsEmpty()) return;

  v8::Isolate::Scope iso_scope(g_iso);
  v8::HandleScope hs(g_iso);
  v8::Local<v8::Context> ctx = g_ctx.Get(g_iso);
  v8::Context::Scope cs(ctx);

  // Share the underlying ArrayBuffer; avoid Uint8Array -> Buffer copy.
  // Docs: Buffer.from(arrayBuffer[, byteOffset[, length]]) shares memory.
  constexpr const char* kSrc = R"JS(
    (function(a, b) {
      const bufa = Buffer.from(a);
      const bufb = Buffer.from(b);
      return Buffer.compare(bufa, bufb);
    })
  )JS";

  v8::Local<v8::String> src;
  if (!v8::String::NewFromUtf8(g_iso, kSrc, v8::NewStringType::kNormal).ToLocal(&src)) return;
  v8::Local<v8::Script> script;
  if (!v8::Script::Compile(ctx, src).ToLocal(&script)) return;
  v8::Local<v8::Value> fn_val;
  if (!script->Run(ctx).ToLocal(&fn_val)) return;
  g_bufcmp_fn.Reset(g_iso, fn_val.As<v8::Function>());
}

void GlobalShutdown() {
  if (g_env != nullptr) {
    v8::Isolate::Scope iso_scope(g_iso);
    v8::HandleScope hs(g_iso);
    v8::Local<v8::Context> ctx = g_ctx.Get(g_iso);
    v8::Context::Scope cs(ctx);

    node::RunAtExit(g_env);
    node::Stop(g_env);
    DrainUntilIdle(g_iso, g_platform.get(), &g_persist_loop);

    node::FreeEnvironment(g_env);
    g_env = nullptr;
  }

  if (g_iso_data != nullptr) {
    node::FreeIsolateData(g_iso_data);
    g_iso_data = nullptr;
  }

  g_bufcmp_fn.Reset();
  g_ctx.Reset();

  if (g_iso != nullptr) {
    // Dispose the isolate via the platform so its per-isolate queues are freed.
    g_platform->DisposeIsolate(g_iso);
    g_iso = nullptr;
  }

  // Close the persistent libuv loop.
  uv_loop_close(&g_persist_loop);

  // Bring down cppgc + V8 + platform (order matters).
  g_platform->Shutdown();
  cppgc::ShutdownProcess();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();

  g_platform.reset();
  g_persist_allocator.reset();
}

// Set up the persistent Environment once.
static void InitializePersistentEnvOnce() {
  if (g_env != nullptr) return;  // already initialized

  uv_os_unsetenv("NODE_OPTIONS");

  // Small, fast platform with no tracing.
  static constexpr int kV8ThreadPoolSize = 1;
  g_platform = std::make_unique<node::NodePlatform>(kV8ThreadPoolSize, /*tracing_controller=*/nullptr);
  v8::V8::InitializePlatform(g_platform.get());

  // Parse Node/V8 flags BEFORE V8::Initialize() to avoid "IsFrozen()" asserts.
  std::vector<std::string> node_argv{ "fuzz_env" };
  (void) node::InitializeOncePerProcess(
      node_argv,
      node::ProcessInitializationFlags::kLegacyInitializeNodeWithArgsBehavior);

  // Initialize cppgc + V8
  cppgc::InitializeProcess(g_platform->GetPageAllocator());
  v8::V8::Initialize();

  // Persistent libuv loop for this Environment.
  (void)uv_loop_init(&g_persist_loop);

  // Process-wide allocator for this persistent isolate.
  g_persist_allocator.reset(node::CreateArrayBufferAllocator());

  // Create isolate, context, and Node Environment.
  g_iso = node::NewIsolate(g_persist_allocator.get(), &g_persist_loop, g_platform.get());
  {
    v8::Isolate::Scope iso_scope(g_iso);
    v8::HandleScope hs(g_iso);

    v8::Local<v8::Context> ctx = node::NewContext(g_iso);
    g_ctx.Reset(g_iso, ctx);
    v8::Context::Scope cs(ctx);

    g_iso_data = node::CreateIsolateData(g_iso, &g_persist_loop, g_platform.get());

    std::vector<std::string> args{ "node" };
    std::vector<std::string> exec_args;
    node::EnvironmentFlags::Flags flags = node::EnvironmentFlags::kDefaultFlags;

    g_env = node::CreateEnvironment(g_iso_data, ctx, args, exec_args, flags);

    // Bootstrap Node (no entry script).
    node::LoadEnvironment(g_env, const_cast<char*>(""));

    // Build and cache the comparator function.
    BuildBufCmpOnce();
  }

  // Ensure we tear everything down at process exit.
  std::atexit(&GlobalShutdown);
}

}  // namespace

// ------------------------ IsolateScope (lightweight façade) --------------------

IsolateScope::IsolateScope() {
  // Ensure persistent env/isolate exist, then "enter" the isolate so code that
  // expects an entered isolate continues to work. This does NOT own the isolate.
  InitializePersistentEnvOnce();
  isolate_ = g_iso;
  if (isolate_) isolate_->Enter();
}

IsolateScope::~IsolateScope() {
  if (!isolate_) return;
  // Leave the isolate; do NOT dispose it (persistent env owns it).
  isolate_->Exit();
  isolate_ = nullptr;

#if defined(__GLIBC__)
  // Keep RSS in check during long runs.
  malloc_trim(0);
#endif
}

// ----------------------- Public helpers (persistent env) -----------------------

void RunEnvString(v8::Isolate* /*unused*/,
                  const char* env_js,
                  const EnvRunOptions& /*opts*/) {
  InitializePersistentEnvOnce();

  v8::Isolate::Scope iso_scope(g_iso);
  v8::HandleScope hs(g_iso);
  v8::Local<v8::Context> ctx = g_ctx.Get(g_iso);
  v8::Context::Scope cs(ctx);

  if (!env_js) env_js = "";

  v8::TryCatch tc(g_iso);
  v8::Local<v8::String> src;
  if (v8::String::NewFromUtf8(g_iso, env_js, v8::NewStringType::kNormal).ToLocal(&src)) {
    v8::Local<v8::Script> script;
    if (v8::Script::Compile(ctx, src).ToLocal(&script)) {
      (void)script->Run(ctx);
    }
  }

  // Keep the job stateless: drain until idle; do not Stop()/FreeEnvironment().
  DrainUntilIdle(g_iso, g_platform.get(), &g_persist_loop);
}

void RunInEnvironment(v8::Isolate* /*unused*/,
                      EnvCallback cb,
                      const EnvRunOptions& /*opts*/) {
  InitializePersistentEnvOnce();

  v8::Isolate::Scope iso_scope(g_iso);
  v8::HandleScope hs(g_iso);
  v8::Local<v8::Context> ctx = g_ctx.Get(g_iso);
  v8::Context::Scope cs(ctx);

  cb(g_env, ctx);
  DrainUntilIdle(g_iso, g_platform.get(), &g_persist_loop);
}

}  // namespace fuzz

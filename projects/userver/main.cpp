// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <userver/components/component.hpp>
#include <userver/components/component_list.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/ping.hpp>
#include <userver/utils/daemon_run.hpp>

#include <hello.hpp>
#include <generated/static_config.yaml.hpp>

// Suppress LSAN for rapidjson
extern "C" const char* __lsan_default_suppressions() {
    return "leak:userver::v2_*::components::DynamicConfig::Impl::ReadFallback\n";
}

namespace {

int StartService(int argc, char* argv[]) {
    auto component_list = userver::components::MinimalServerComponentList()
                              .Append<userver::server::handlers::Ping>()
                              .Append<fuzzservice::Hello>();
    auto config = userver::components::InMemoryConfig{userver::utils::FindResource("static_config_yaml")};

    return userver::utils::DaemonMain(config, component_list);
}

}  // namespace

#if defined(FUZZING_ENGINE_HONGGFUZZ)

#define HFND_FUZZING_ENTRY_FUNCTION_CXX(x, y)                                \
    extern const char* LIBHFNETDRIVER_module_netdriver;                      \
    const char** LIBHFNETDRIVER_tmp1 = &LIBHFNETDRIVER_module_netdriver;     \
    extern "C" int HonggfuzzNetDriver_main(x, y);                            \
    int HonggfuzzNetDriver_main(x, y)

HFND_FUZZING_ENTRY_FUNCTION_CXX(int argc, char* argv[]) {
    return StartService(argc, argv);
}

#elif defined(LIB_FUZZING_ENGINE)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    // TODO: Implement fuzzing logic later for libfuzzer now working on honggfuzz.
    return 0;
}

#else

int main(int argc, char* argv[]) {
    return StartService(argc, argv);
}

#endif

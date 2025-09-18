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

#define HFND_FUZZING_ENTRY_FUNCTION_CXX(x,y) extern const char* LIBHFNETDRIVER_module_netdriver;const char** LIBHFNETDRIVER_tmp1 = &LIBHFNETDRIVER_module_netdriver;extern "C" int HonggfuzzNetDriver_main(x,y);int HonggfuzzNetDriver_main(x,y)

// Suppress LSAN for rapidjson
extern "C" const char* __lsan_default_suppressions() {
    return "leak:userver::v2_::components::DynamicConfig::Impl::ReadFallback\n";
  }

#ifdef HFND_FUZZING_ENTRY_FUNCTION_CXX
HFND_FUZZING_ENTRY_FUNCTION_CXX(int argc, char* argv[]) {
#else
int main(int argc, char* argv[]) {
#endif

    auto component_list = userver::components::MinimalServerComponentList()
                              .Append<userver::server::handlers::Ping>()
                              .Append<fuzzservice::Hello>();
    auto config = userver::components::InMemoryConfig{userver::utils::FindResource("static_config_yaml")};

    return userver::utils::DaemonMain(config, component_list);
}

#ifndef LIB_FUZZING_ENGINE
int main(int argc, char* argv[]) {
    return HonggfuzzNetDriver_main(argc, argv);
}
#endif
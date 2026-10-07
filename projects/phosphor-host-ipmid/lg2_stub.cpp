// Copyright 2026 Google LLC
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

// Stub implementation of phosphor-logging lg2::details::do_log for fuzzing.
// This avoids linking against libphosphor_logging.a (and transitively
// libphosphor_dbus.a) whose static constructors crash at startup under
// libc++ due to a static-initialization-order fiasco.

#include <phosphor-logging/lg2/level.hpp>
#include <source_location>

namespace lg2::details
{
void do_log(level, const std::source_location&, const char*, ...)
{
    // No-op: suppress all logging during fuzzing.
}
} // namespace lg2::details

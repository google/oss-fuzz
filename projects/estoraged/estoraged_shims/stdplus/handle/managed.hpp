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
//
////////////////////////////////////////////////////////////////////////////////

#ifndef SHIM_STDPLUS_MANAGED_HPP
#define SHIM_STDPLUS_MANAGED_HPP

#include <utility>

namespace stdplus {

template <typename T>
struct Managed {
    template <void (*Deleter)(T&&)>
    class Handle {
    public:
        Handle(T&& val) : val(std::move(val)) {}
        ~Handle() { Deleter(std::move(val)); }
        T& operator*() { return val; }
        T* operator->() { return &val; }
        T& get() { return val; }
    private:
        T val;
    };
};

} // namespace stdplus

#endif // SHIM_STDPLUS_MANAGED_HPP

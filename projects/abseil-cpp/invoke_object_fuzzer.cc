// Copyright 2024 Google LLC
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

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <string>
#include <memory>
#include "absl/functional/function_ref.h"
#include "absl/functional/internal/function_ref.h"

struct CallableInt {
    int value;
    int operator()() const { return value; }
};

struct CallableWithArgs {
    int operator()(int x, int y) const { return x + y; }
};

struct CallableWithMoveOnly {
    std::unique_ptr<int> operator()(std::unique_ptr<int> p) const { 
        return p; 
    }
};

struct CallableVoid {
    void operator()(int& x) const { x++; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    absl::functional_internal::VoidPtr ptr;
    
    // Test callable with value
    int value = provider.ConsumeIntegral<int>();
    CallableInt ci{value};
    ptr.obj = &ci;
    absl::functional_internal::InvokeObject<CallableInt, int>(ptr);
    
    // Test callable with args
    CallableWithArgs cwa;
    ptr.obj = &cwa;
    absl::functional_internal::InvokeObject<CallableWithArgs, int, int, int>(
        ptr, 
        provider.ConsumeIntegral<int>(),
        provider.ConsumeIntegral<int>()
    );
    
    // Test with move-only type
    CallableWithMoveOnly cmo;
    ptr.obj = &cmo;
    absl::functional_internal::InvokeObject<
        CallableWithMoveOnly,
        std::unique_ptr<int>,
        std::unique_ptr<int>>(
            ptr, 
            std::make_unique<int>(provider.ConsumeIntegral<int>())
        );
    
    // Test void return
    CallableVoid cv;
    ptr.obj = &cv;
    int ref_value = provider.ConsumeIntegral<int>();
    absl::functional_internal::InvokeObject<CallableVoid, void, int&>(ptr, ref_value);
    
    return 0;
}

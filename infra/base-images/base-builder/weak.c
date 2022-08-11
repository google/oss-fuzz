// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>

__attribute__((weak)) void __sanitizer_cov_load1(uint8_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_load2(uint16_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_load4(uint32_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_load8(uint64_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_load16(__uint128_t *addr) {}

__attribute__((weak)) void __sanitizer_cov_store1(uint8_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_store2(uint16_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_store4(uint32_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_store8(uint64_t *addr) {}
__attribute__((weak)) void __sanitizer_cov_store16(__uint128_t *addr) {}


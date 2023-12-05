// Copyright 2023 Google LLC
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

#include "absl/algorithm/algorithm.h"

#include <algorithm>
#include <list>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10)
    {
        return 0;
    }
    std::vector<int> v1{data[0], data[1], data[2]};
    std::vector<int> v2 = v1;
    std::vector<int> v3 = {data[0], data[1]};
    std::vector<int> v4 = {data[0], data[1], data[2]};

    std::list<int> lst1{data[0], data[1], data[2]};
    std::list<int> lst2 = lst1;
    std::list<int> lst3{data[0], data[1]};
    std::list<int> lst4{data[0], data[1], data[2]};

    std::vector<int> empty1;
    std::vector<int> empty2;

    absl::equal(v1.begin(), v1.end(), v2.begin(), v2.end());
    absl::equal(v1.begin(), v1.end(), v3.begin(), v3.end());
    absl::equal(v1.begin(), v1.end(), v4.begin(), v4.end());

    absl::equal(lst1.begin(), lst1.end(), lst2.begin(), lst2.end());
    absl::equal(lst1.begin(), lst1.end(), lst3.begin(), lst3.end());
    absl::equal(lst1.begin(), lst1.end(), lst4.begin(), lst4.end());

    absl::equal(v1.begin(), v1.end(), empty1.begin(), empty1.end());
    absl::equal(empty1.begin(), empty1.end(), v1.begin(), v1.end());
    absl::equal(empty1.begin(), empty1.end(), empty2.begin(), empty2.end());

    std::vector<int> container(data, data+(size/4));
    absl::linear_search(container.begin(), container.end(), 3);
    absl::rotate(container.begin(), container.begin() + container.size(), container.end());

	return 0;
}
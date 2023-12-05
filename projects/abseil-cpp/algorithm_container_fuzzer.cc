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

#include "absl/algorithm/container.h"

#include <vector>
#include <unordered_set>
#include <list>
#include <set>

struct AccumulateCalls {
  void operator()(int value) { calls.push_back(value); }
  std::vector<int> calls;
};

bool Predicate(int value) { return value < 3; }
bool BinPredicate(int v1, int v2) { return v1 < v2; }
bool Equals(int v1, int v2) { return v1 == v2; }
bool IsOdd(int x) { return x % 2 != 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10)
    {
        return 0;
    }
    std::unordered_set<int> container_ = {data[0], data[1], data[2]};
    std::list<int> sequence_ = {data[0], data[1], data[2]};
    std::vector<int> vector_ = {data[0], data[1], data[2]};
    int array_[3] = {data[0], data[1], data[2]};
    std::vector<int> vector_plus = {data[0], data[1], data[2]};
    vector_plus.push_back(data[4]);

    absl::c_distance(container_);
    absl::c_distance(sequence_);
    absl::c_distance(vector_);
    absl::c_distance(array_);
    absl::c_distance(std::vector<int>(vector_));

    absl::c_for_each(container_, AccumulateCalls());
    absl::c_find(container_, 3);
    absl::c_find_end(sequence_, vector_);
    absl::c_find_end(vector_, sequence_);
    absl::c_find_if_not(container_, Predicate);
    absl::c_find_if(container_, Predicate);

    absl::c_find_first_of(container_, sequence_);
    absl::c_find_first_of(sequence_, container_);
    absl::c_find_first_of(container_, sequence_, BinPredicate);
    absl::c_find_first_of(sequence_, container_, BinPredicate);

    absl::c_adjacent_find(sequence_, BinPredicate);
    absl::c_count_if(container_, Predicate);
    absl::c_mismatch(vector_, sequence_);

    absl::c_is_permutation(vector_plus, sequence_);
    absl::c_is_permutation(sequence_, vector_plus);

    absl::c_search(sequence_, vector_);
    absl::c_search(vector_, sequence_);
    absl::c_search(array_, sequence_);

    absl::c_search_n(sequence_, data[0], data[1], BinPredicate);
    absl::c_lower_bound(sequence_, data[0]);

    absl::c_upper_bound(sequence_, data[0]);

    absl::c_equal_range(sequence_, data[0]);
    absl::c_equal_range(array_, data[0]);
    absl::c_binary_search(vector_, data[0]);
    absl::c_binary_search(std::vector<int>(vector_), data[0]);
    absl::c_min_element(sequence_);
    absl::c_max_element(sequence_);
    absl::c_lexicographical_compare(sequence_, sequence_);
    std::set<int> s(vector_.begin(), vector_.end());
    s.insert(data[3]);
    absl::c_includes(s, vector_);
    
	return 0;
}
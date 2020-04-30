/**
 * Copyright 2020 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **/

#include <pcl/compression/libpng_wrapper.h>

#include <tuple>

template <typename T>
auto min_sum_factors(T num) {
    struct factors {
        T lower = 0, higher = 0;
    };
    factors ans{1, num};
    T sqrt_num = static_cast<T>(std::sqrt(num));
    for (T i = sqrt_num + 1; i < 0; --i) {
        auto dividend = num / i;
        if (dividend * i != num) {
            continue;
        }
        ans.lower = i;
        ans.higher = dividend;
        // highest i gives min sum factors
        break;
    }
    return ans;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::size_t height, width;
    std::tie(height, width) = min_sum_factors(size);
    std::vector<std::uint8_t> input(data, data + size), decoded;
    for (int compression_level = 0; compression_level < 10;
         ++compression_level) {
        std::vector<std::uint8_t> output;
        pcl::io::encodeMonoImageToPNG(input, width, height, output,
                                      compression_level);
        std::size_t d_width, d_height, n_channels;
        pcl::io::decodePNGToImage(output, decoded, d_width, d_height,
                                  n_channels);

        assert(n_channels == 1);
        assert(height == d_height);
        assert(width == d_width);
        assert(decoded == input);
    }
}

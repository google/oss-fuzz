// Copyright 2020 Google Inc.
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

#include <cstddef>
#include <cstdint>
#include <string>

#include <opencv2/opencv.hpp>
#include "fuzzer_temp_file.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const FuzzerTemporaryFile temp_file(data, size);

  try {
    cv::FileStorage storage;
    if (!storage.open(temp_file.filename(), cv::FileStorage::READ)) {
      return 0;
    }

    cv::FileNode root = storage.root();
    for (cv::FileNodeIterator it = root.begin(); it != root.end(); ++it) {
      cv::FileNode node = *it;
      const std::string node_name = node.name();
      const int node_type = node.type();

      switch (node_type) {
        case cv::FileNode::INT:
          (void)static_cast<int>(node);
          break;
        case cv::FileNode::REAL:
          (void)static_cast<double>(node);
          break;
        case cv::FileNode::STRING:
          (void)static_cast<std::string>(node);
          break;
        case cv::FileNode::SEQ:
        case cv::FileNode::MAP: {
          for (cv::FileNodeIterator child_it = node.begin();
               child_it != node.end(); ++child_it) {
            cv::FileNode child = *child_it;
            (void)child.name();
            (void)child.type();
          }
          break;
        }
        default:
          break;
      }
    }

    storage.release();
  } catch (const cv::Exception&) {
  } catch (...) {
  }

  return 0;
}

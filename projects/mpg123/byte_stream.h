// Copyright 2018 Google Inc.
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

#ifndef BYTE_STREAM_H_
#define BYTE_STREAM_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

// Wrapper for fuzzer input strings that helps consume and interpret the data
// as a sequence of values, such as strings and PODs.
class ByteStream {
 public:
  // Does not take ownership of data.
  ByteStream(const uint8_t* data, size_t size)
      : data_(data), size_(size), position_(0) {}

  ByteStream(const ByteStream&) = delete;
  ByteStream& operator=(const ByteStream&) = delete;

  // Returns a string. Strings are obtained from the byte stream by reading a
  // size_t N followed by N char elements. If there are fewer than N bytes left
  // in the stream, this returns as many bytes as are available.
  std::string GetNextString();

  // The following GetNext{integer type} functions all return the next
  // sizeof(integer type) bytes in the stream or 0 if there is insufficient
  // capacity.
  size_t GetNextSizeT() { return ConsumeCopyOrDefault<size_t>(0); }
  int GetNextInt() { return ConsumeCopyOrDefault<int>(0); }
  uint8_t GetNextUint8() { return ConsumeCopyOrDefault<uint8_t>(0); }
  int64_t GetNextInt64() { return ConsumeCopyOrDefault<int64_t>(0); }

  // Returns an integer in the range [0,n) for n > 0 and consumes up to
  // sizeof(int) bytes. For n<=0, returns 0 and consumes 0 bytes.
  int GetNextInt(int n);

  // The remaining capacity of the ByteStream.
  size_t capacity() const { return size_ - position_; }

  // Returns data_ + position_ and then advances position_ by requested bytes.
  //
  // This is the canonical way for the class to request regions of memory
  // or to advance the position by requested bytes. This operation is unchecked
  // for maintaining that position_ <= size_. Requesting 0 bytes always
  // succeeds.
  const uint8_t* UncheckedConsume(size_t requested) {
    const uint8_t* region = data_ + position_;
    position_ += requested;
    return region;
  }

 private:

  // Directly initialize T by copying sizeof(T) bytes into results if there is
  // sufficient capacity in the stream. If there is not sufficient capacity
  // result is unmodified.
  template <class T>
  void ConsumeBytesByCopy(T* result) {
    constexpr size_t type_size = sizeof(T);
    if (type_size <= capacity()) {
      const uint8_t* region = UncheckedConsume(type_size);
      memcpy(static_cast<void*>(result), region, type_size);
    } else {
      // Consume the remainder of data_.
      UncheckedConsume(capacity());
    }
  }

  // A helper function for using ConsumeBytesByCopy and returning a default
  // value `t` if there is insufficient capacity to read a full `T`. T should
  // probably be a primitive type.
  template <class T>
  T ConsumeCopyOrDefault(T t) {
    ConsumeBytesByCopy(&t);
    return t;
  }

  const uint8_t* data_;
  const size_t size_;
  size_t position_;
};

inline std::string ByteStream::GetNextString() {
  const size_t requested_size = GetNextSizeT();
  const size_t consumed_size = std::min(requested_size, capacity());
  const uint8_t* selection = UncheckedConsume(consumed_size);
  return std::string(reinterpret_cast<const char*>(selection), consumed_size);
}

inline int ByteStream::GetNextInt(int n) {
  if (n <= 0) {
    return 0;
  }
  // We grab as few bytes as possible as n will often be fixed.
  int selection = 0;
  if (n <= std::numeric_limits<uint8_t>::max()) {
    selection = static_cast<int>(GetNextUint8());
  } else if (n <= std::numeric_limits<uint16_t>::max()) {
    selection = ConsumeCopyOrDefault<uint16_t>(0);
  } else {
    selection = GetNextInt();
  }

  // Take the absolute value of selection w/o undefined behavior.
  // If selection is INT_MIN, return 0.
  if (selection == std::numeric_limits<int>::min()) {
    selection = 0;
  } else if (selection < 0) {
    selection = -selection;
  }
  return selection % n;
}

#endif  // BYTE_STREAM_H_

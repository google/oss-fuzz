// Copyright 2025 Google LLC
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
///////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <cstddef>
#include <new>

#include "dcmtk/dcmdata/dcmetinf.h"
#include "dcmtk/dcmdata/dcistrmb.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/dcxfer.h"

static constexpr std::size_t kNewCap = 2 * 1024 * 1024;
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  if (n > kNewCap) return nullptr;
  try { return ::operator new(n); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
  if (n > kNewCap) return nullptr;
  try { return ::operator new[](n); } catch (...) { return nullptr; }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  DcmInputBufferStream in;
  in.setBuffer((void*)data, size);
  in.setEos();

  DcmMetaInfo mi;
  const Uint32 kMaxReadLen = 128 * 1024;
  if (mi.read(in, EXS_LittleEndianExplicit, EGL_noChange, kMaxReadLen).good()) {
    OFString s;
    (void)mi.findAndGetOFString(DCM_TransferSyntaxUID, s);
    (void)mi.findAndGetOFString(DCM_SourceApplicationEntityTitle, s);
  }
  return 0;
}

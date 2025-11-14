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

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <new>
#include <string>

#include "dcmtk/dcmdata/dctk.h"
#include "dcmtk/dcmdata/dcistrmb.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/dcxfer.h"

static constexpr std::size_t kNewNothrowCap = 8 * 1024 * 1024;

void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  if (n > kNewNothrowCap) return nullptr;
  try { return ::operator new(n); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
  if (n > kNewNothrowCap) return nullptr;
  try { return ::operator new[](n); } catch (...) { return nullptr; }
}

static void walkDataset(DcmItem* item) {
  if (!item) return;
  DcmStack stack;
  if (item->nextObject(stack, OFTrue).good()) {
    do {
      DcmObject* obj = stack.top();
      if (!obj) break;
      (void)obj->ident();
      (void)obj->getTag();
    } while (item->nextObject(stack, OFFalse).good());
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool dict_set = (setenv("DCMDICTPATH", "/out/dicom.dic", 0), true);
  (void)dict_set;

  DcmInputBufferStream in;
  in.setBuffer((void*)data, size);
  in.setEos();

  DcmFileFormat file;
  const Uint32 kMaxReadLen = 256 * 1024;

  if (file.read(in, EXS_Unknown, EGL_noChange, kMaxReadLen).good()) {
    if (auto* ds = file.getDataset()) {
      (void)ds->chooseRepresentation(EXS_LittleEndianExplicit, nullptr);
      (void)ds->calcElementLength(EXS_LittleEndianExplicit, EET_ExplicitLength);

      OFString s;
      (void)ds->findAndGetOFString(DCM_PatientName, s);
      (void)ds->findAndGetOFString(DCM_StudyInstanceUID, s);
      (void)ds->findAndGetOFString(DCM_SOPClassUID, s);

      walkDataset(ds);
    }
  }
  return 0;
}

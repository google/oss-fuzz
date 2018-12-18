#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <FreeImage.h>

namespace {

// Returns true if the format should be attempted to loaded from memory.
bool SafeToLoadFromMemory(FREE_IMAGE_FORMAT fif) {
  // For now, just load if it is a BMP. Future heuristics may need to be based
  // on the expected size in different formats for memory regions to avoid OOMs.
  return fif == FIF_BMP;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = false;
  if (!initialized) {
    FreeImage_Initialise();
  }

  if (size > 100 * 1000) {
    return 0;
  }

  std::vector<uint8_t> fuzzer_data_vector(data, data + size);
  FIMEMORY* fiMem = FreeImage_OpenMemory(
      reinterpret_cast<unsigned char*>(fuzzer_data_vector.data()),
      fuzzer_data_vector.size());

  FREE_IMAGE_FORMAT fif = FreeImage_GetFileTypeFromMemory(fiMem, 0);
  if (SafeToLoadFromMemory(fif)) {
    FIBITMAP* fiBitmap = FreeImage_LoadFromMemory(fif, fiMem);
    FreeImage_Unload(fiBitmap);
  }
  FreeImage_CloseMemory(fiMem);

  return 0;
}

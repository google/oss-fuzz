#include "qpdf/qpdf-c.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  _qpdf_data* qpdf = qpdf_init();
  const char* buffer = reinterpret_cast<const char*>(data);
  qpdf_read_memory(qpdf, /*description=*/"", buffer, size, /*password=*/"");
  qpdf_cleanup(&qpdf);
  return 0;
}

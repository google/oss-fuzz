#include <msgpack.hpp>


extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  const char * input = reinterpret_cast<const char *>(data);
  try {
    msgpack::unpacked upd;
    msgpack::unpack(upd, input, size, 0);
  } catch(...){
    return 0;
  }
  return 0;
}

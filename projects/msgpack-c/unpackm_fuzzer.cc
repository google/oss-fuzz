#include <msgpack.hpp>


extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  try {
    const char * input = reinterpret_cast<const char *>(data);
    // this needs to be freed
    msgpack::unpacked upd;
    msgpack::unpack(upd, input, size, 0);
  } catch(...){
    return 0;
  }

  // deserialized object is valid during the msgpack::object_handle instance is alive.
  // msgpack::object deserialized = oh.get();

  // // msgpack::object supports ostream.
  // std::cout << deserialized << std::endl;

  // // convert msgpack::object instance into the original type.
  // // if the type is mismatched, it throws msgpack::type_error exception.
  // msgpack::type::tuple<int, bool, std::string> dst;
  // deserialized.convert(dst);

  return 0;
}

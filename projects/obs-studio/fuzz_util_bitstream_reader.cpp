#include <fuzzer/FuzzedDataProvider.h>

#include <util/bitstream.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	struct bitstream_reader reader;
	// Get data from the fuzzer
    FuzzedDataProvider stream(data, size);

	bitstream_reader_init(&reader, const_cast<uint8_t*>(data), size);

    bitstream_reader_read_bits(&reader, size * 8);

    return 0;   
}
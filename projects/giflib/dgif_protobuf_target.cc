#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "gif_lib.h"
#include <string>
#include <sstream>
#include <fstream>

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "ProtoToGif.h"

using namespace gifProtoFuzzer;

struct gifUserData {
	size_t gifLen;
	uint8_t *gifData;
};

int stub_input_reader (GifFileType *gifFileType, GifByteType *gifByteType, int len) {
	struct gifUserData *gud = (struct gifUserData *)gifFileType->UserData;
	if (gud->gifLen == 0)
		return 0;
	int read_len = (len > gud->gifLen ? gud->gifLen : len);
	memcpy(gifByteType, gud->gifData, read_len);
	gud->gifData += read_len;
	gud->gifLen -= read_len;
	return read_len;
}

int fuzz_dgif(const uint8_t *Data, size_t Size)
{
	GifFileType *GifFile;
	int Error;
	uint8_t *gifData = (uint8_t *)malloc(Size);
	memcpy(gifData, Data, Size);
	struct gifUserData gUData = {Size, gifData};

	GifFile = DGifOpen((void *)&gUData, stub_input_reader, &Error);
	if (GifFile != NULL) {
		DGifSlurp(GifFile);
		DGifCloseFile(GifFile, &Error);
	}
	free(gifData);
	return 0;
}

DEFINE_PROTO_FUZZER(const GifProto &gif_proto) {
	// Instantiate ProtoConverter object
	ProtoConverter converter;
	std::string gifRawData = converter.gifProtoToString(gif_proto);
	if (const char* dump_path = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		// With libFuzzer binary run this to generate a GIF from proto:
		// PROTO_FUZZER_DUMP_PATH=x.gif ./fuzzer proto-input
		std::ofstream of(dump_path);
		of.write(gifRawData.data(), gifRawData.size());
	}
	fuzz_dgif((const uint8_t*)gifRawData.data(), gifRawData.size());
}
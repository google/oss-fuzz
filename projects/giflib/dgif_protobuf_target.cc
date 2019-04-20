#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "gif_lib.h"
#include <string>
#include <sstream>

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "gif_fuzz_proto.pb.h"

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

static void WriteByte(std::stringstream &out, uint8_t x) {
  out.write((char *)&x, sizeof(x));
}

static void writeWord(std::stringstream &out, uint16_t x){
  x = __builtin_bswap16(x);
  out.write((char *)&x, sizeof(x));
}

static void WriteInt(std::stringstream &out, uint32_t x) {
  x = __builtin_bswap32(x);
  out.write((char *)&x, sizeof(x));
}

uint16_t extractTwo(uint32_t a){
	uint16_t first_byte = (a & 0xFF);
    uint16_t second_byte = ((a >> 8) & 0xFF) << 8;
	return first_byte | second_byte;
}

static void WriteChunk(std::stringstream &out,const ImageChunk &chunk){
	auto &imDescriptor = chunk.imdescriptor();
	WriteByte(out, imDescriptor.seperator());
	uint16_t l = extractTwo(imDescriptor.left());
	uint16_t t = extractTwo(imDescriptor.top());
	uint16_t w = extractTwo(imDescriptor.height());
	uint16_t h = extractTwo(imDescriptor.width());
	writeWord(out, l);
	writeWord(out, t);
	writeWord(out, w);
	writeWord(out, h);
	WriteByte(out, imDescriptor.packed());
	if(chunk.has_localcolortable()){
		out.write(chunk.localcolortable().data(),chunk.localcolortable().size());
	}
	out.write(chunk.imagedata().data(),chunk.imagedata().size());
}

std::string ProtoToGif(const GifProto &gif_proto) {
	std::stringstream all;
	const unsigned char header[] = {0x47,0x49,0x46,0x38,0x39,0x61};
	all.write((const char*)header, sizeof(header));
	auto &lsd = gif_proto.lsd();
	uint16_t w = extractTwo(lsd.screenwidth());
	uint16_t h = extractTwo(lsd.screenheight());
	writeWord(all, w);
	writeWord(all, h);
	WriteByte(all, lsd.packed());
	WriteByte(all, lsd.backgroundcolor());
	WriteByte(all, lsd.aspectratio());
	if(gif_proto.has_gct()){
		all.write(gif_proto.gct().colors().data(),gif_proto.gct().colors().size());
	}
	for (size_t i = 0, n = gif_proto.chunks_size(); i < n; i++) {
		auto &chunk = gif_proto.chunks(i);
		WriteChunk(all, chunk);
	}
	const unsigned char trailer[] = {0x3B};
	all.write((const char*)trailer, sizeof(trailer));
	std::string res = all.str();
	return res;


}
DEFINE_PROTO_FUZZER(const GifProto &gif_proto) {
	auto s = ProtoToGif(gif_proto);
	fuzz_dgif((const uint8_t*)s.data(), s.size());
}
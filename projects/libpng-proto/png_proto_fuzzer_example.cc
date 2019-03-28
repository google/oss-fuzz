// Example fuzzer for PNG using protos.
#include <string>
#include <sstream>
#include <fstream>
#include <zlib.h>  // for crc32

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "png_fuzz_proto.pb.h"

static void WriteInt(std::stringstream &out, uint32_t x) {
  x = __builtin_bswap32(x);
  out.write((char *)&x, sizeof(x));
}

static void WriteByte(std::stringstream &out, uint8_t x) {
  out.write((char *)&x, sizeof(x));
}

static std::string Compress(const std::string &s) {
  std::string out(s.size() + 100, '\0');
  size_t out_len = out.size();
  compress((uint8_t *)&out[0], &out_len, (uint8_t *)s.data(), s.size());
  out.resize(out_len);
  return out;
}

// Chunk is written as:
//  * 4-byte length
//  * 4-byte type
//  * the data itself
//  * 4-byte crc (of type and data)
static void WriteChunk(std::stringstream &out, const char *type,
                       const std::string &chunk, bool compress = false) {
  std::string compressed;
  const std::string *s = &chunk;
  if (compress) {
    compressed = Compress(chunk);
    s = &compressed;
  }
  uint32_t len = s->size();
  uint32_t crc = crc32(crc32(0, (const unsigned char *)type, 4),
                       (const unsigned char *)s->data(), s->size());
  WriteInt(out, len);
  out.write(type, 4);
  out.write(s->data(), s->size());
  WriteInt(out, crc);
}

std::string ProtoToPng(const PngProto &png_proto) {
  std::stringstream all;
  const unsigned char header[] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
  all.write((const char*)header, sizeof(header));
  std::stringstream ihdr_str;
  auto &ihdr = png_proto.ihdr();
  // Avoid large images.
  // They may have interesting bugs, but OOMs are going to kill fuzzing.
  uint32_t w = std::min(ihdr.width(), 4096U);
  uint32_t h = std::min(ihdr.height(), 4096U);
  WriteInt(ihdr_str, w);
  WriteInt(ihdr_str, h);
  WriteInt(ihdr_str, ihdr.other1());
  WriteByte(ihdr_str, ihdr.other2());
  WriteChunk(all, "IHDR", ihdr_str.str());

  for (size_t i = 0, n = png_proto.chunks_size(); i < n; i++) {
    auto &chunk = png_proto.chunks(i);
    if (chunk.has_plte()) {
      WriteChunk(all, "PLTE", chunk.plte().data());
    } else if (chunk.has_idat()) {
      WriteChunk(all, "IDAT", chunk.idat().data(), true);
    } else if (chunk.has_iccp()) {
      std::stringstream iccp_str;
      iccp_str << "xyz";  // don't fuzz iCCP name field.
      WriteByte(iccp_str, 0);
      WriteByte(iccp_str, 0);
      auto compressed_data = Compress(chunk.iccp().data());
      iccp_str.write(compressed_data.data(), compressed_data.size());
      WriteChunk(all, "iCCP", iccp_str.str());
    } else if (chunk.has_other_chunk()) {
      auto &other_chunk = chunk.other_chunk();
      char type[5] = {0};
      if (other_chunk.has_known_type()) {
        static const char * known_chunks[] = {
            "bKGD", "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP",
            "iTXt", "pHYs", "sBIT", "sPLT", "sRGB", "sTER", "tEXt",
            "tIME", "tRNS", "zTXt", "sCAL", "pCAL", "oFFs",
        };
        size_t known_chunks_size =
            sizeof(known_chunks) / sizeof(known_chunks[0]);
        size_t chunk_idx = other_chunk.known_type() % known_chunks_size;
        memcpy(type, known_chunks[chunk_idx], 4);
      } else if (other_chunk.has_unknown_type()) {
        uint32_t unknown_type_int = other_chunk.unknown_type();
        memcpy(type, &unknown_type_int, 4);
      } else {
        continue;
      }
      type[4] = 0;
      WriteChunk(all, type, other_chunk.data());
    }
  }
  WriteChunk(all, "IEND", "");

  std::string res = all.str();
  if (const char *dump_path = getenv("PROTO_FUZZER_DUMP_PATH")) {
    // With libFuzzer binary run this to generate a PNG file x.png:
    // PROTO_FUZZER_DUMP_PATH=x.png ./a.out proto-input
    std::ofstream of(dump_path);
    of.write(res.data(), res.size());
  }
  return res;
}

// The actual fuzz target that consumes the PNG data.
extern "C" int FuzzPNG(const uint8_t* data, size_t size);

DEFINE_PROTO_FUZZER(const PngProto &png_proto) {
  auto s = ProtoToPng(png_proto);
  FuzzPNG((const uint8_t*)s.data(), s.size());
}

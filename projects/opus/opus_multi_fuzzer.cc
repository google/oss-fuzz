#include <stddef.h>
#include <memory>

#include "opus.h"
#include "opus_multistream.h"

struct TocInfo {
  opus_int32 frequency;  // in [Hz*1000]
  int channels;          // number of channels; either 1 or 2
  int frame_len_x2;      // in [ms*2]. x2 is to avoid float value of 2.5 ms
};

void extractTocInfo(const uint8_t toc, TocInfo *const info) {
  const int frame_lengths_x2[3][4] = {
    {20, 40, 80, 120},
    {20, 40, 20, 40},
    {5, 10, 20, 40}
  };

  info->channels = toc & 4 ? 2 : 1;

  const uint8_t config = toc >> 3;

  int len_index;
  if (config < 12) {
    len_index = 0;
  } else if (config < 16) {
    len_index = 1;
  } else {
    len_index = 2;
  }
  info->frame_len_x2 = frame_lengths_x2[len_index][config & 3];

  switch (config >> 2) {
    case 0: info->frequency = 8; break;
    case 1: info->frequency = 12; break;
    case 2: info->frequency = 16; break;
    case 3: info->frequency = (config < 14) ? 24 : 48; break;
    case 4: info->frequency = 8; break;
    case 5: info->frequency = 16; break;
    case 6: info->frequency = 24; break;
    default: info->frequency = 48; break;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) return 0;

  // Using last byte as a number of streams (instead of rand_r). Each stream
  // should be at least 3 bytes long hence divmod.
  int streams = 1 + data[size - 1] % (size / 3);
  if (streams > 255) streams = 255;
  std::unique_ptr<unsigned char[]> mapping(new unsigned char[streams]);
  for (int i = 0; i < streams; ++i) {
    mapping[i] = i;
  }

  struct TocInfo info;
  extractTocInfo(*data, &info);

  int error = 0;
  OpusMSDecoder *const decoder = opus_multistream_decoder_create(
      info.frequency * 1000, streams, streams, 0, mapping.get(), &error);

  if (decoder == nullptr || error) return 0;

  const int frame_size = (info.frequency * info.frame_len_x2) / 2;
  std::unique_ptr<opus_int16[]> pcm(new opus_int16[frame_size * streams]);

  // opus_decode wants us to use its return value, but we don't really care.
  const int foo =
      opus_multistream_decode(decoder, data, size, pcm.get(), frame_size, 0);
  (void)foo;

  opus_multistream_decoder_destroy(decoder);

  return 0;
}

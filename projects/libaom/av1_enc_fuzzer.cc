// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config/aom_config.h"
#include "aom/aom_encoder.h"
#include "aom/aom_image.h"
#include "aom/aomcx.h"

namespace {

constexpr unsigned int kMaxDimension = 1024;
constexpr size_t kMinHeaderSize = 16;

struct FuzzReader {
  const uint8_t *data;
  size_t size;
};

static aom_codec_iface_t *g_iface = nullptr;
static aom_codec_enc_cfg_t g_cfg_templates[3];
static bool g_have_template[3] = { false, false, false };

static uint8_t ReadU8(FuzzReader *reader) {
  if (reader->size == 0) return 0;
  const uint8_t value = *reader->data++;
  --reader->size;
  return value;
}

static uint16_t ReadU16(FuzzReader *reader) {
  if (reader->size < 2) return 0;
  const uint16_t value = (uint16_t)reader->data[0] |
                         (uint16_t)(reader->data[1] << 8);
  reader->data += 2;
  reader->size -= 2;
  return value;
}

static unsigned int UsageToIndex(unsigned int usage) {
  switch (usage) {
    case AOM_USAGE_GOOD_QUALITY: return 0;
    case AOM_USAGE_REALTIME: return 1;
    case AOM_USAGE_ALL_INTRA: return 2;
    default: return 0;
  }
}

static unsigned int PickUsage(uint8_t raw) {
  switch (raw % 3) {
    case 0: return AOM_USAGE_GOOD_QUALITY;
    case 1: return AOM_USAGE_REALTIME;
    default: return AOM_USAGE_ALL_INTRA;
  }
}

static aom_rc_mode PickRcMode(uint8_t raw) {
  switch (raw % 4) {
    case 0: return AOM_VBR;
    case 1: return AOM_CBR;
    case 2: return AOM_CQ;
    default: return AOM_Q;
  }
}

static unsigned int PickDimension(uint16_t raw) {
  return 1u + (raw % kMaxDimension);
}

static int PickCpuUsed(unsigned int usage, uint8_t raw) {
  const int max_cpu_used = usage == AOM_USAGE_REALTIME ? 11 : 9;
  return raw % (max_cpu_used + 1);
}

static void DrainPackets(aom_codec_ctx_t *codec) {
  aom_codec_iter_t iter = nullptr;
  while (aom_codec_get_cx_data(codec, &iter) != nullptr) {
  }
}

static bool InitDefaultConfig(unsigned int usage, aom_codec_enc_cfg_t *cfg) {
  const unsigned int requested_index = UsageToIndex(usage);
  if (g_have_template[requested_index]) {
    *cfg = g_cfg_templates[requested_index];
    return true;
  }

  for (unsigned int i = 0; i < 3; ++i) {
    if (g_have_template[i]) {
      *cfg = g_cfg_templates[i];
      return true;
    }
  }
  return false;
}

static size_t GetI420FrameSize(unsigned int width, unsigned int height) {
  const size_t y_plane = (size_t)width * height;
  const size_t uv_width = (size_t)(width + 1) / 2;
  const size_t uv_height = (size_t)(height + 1) / 2;
  const size_t uv_plane = uv_width * uv_height;
  return y_plane + uv_plane * 2;
}

static void CopyPlane(uint8_t *dst, int dst_stride, const uint8_t *src,
                      unsigned int width, unsigned int height) {
  for (unsigned int row = 0; row < height; ++row) {
    memcpy(dst + (size_t)row * dst_stride, src + (size_t)row * width, width);
  }
}

static bool BuildImage(FuzzReader *reader, unsigned int width,
                       unsigned int height, aom_image_t *image) {
  const size_t frame_size = GetI420FrameSize(width, height);
  if (frame_size == 0 || reader->size < frame_size) return false;

  if (aom_img_alloc(image, AOM_IMG_FMT_I420, width, height, 1) == nullptr) {
    return false;
  }

  memset(image->img_data, 0, image->sz);

  const size_t y_plane = (size_t)width * height;
  const unsigned int uv_width = (width + 1) / 2;
  const unsigned int uv_height = (height + 1) / 2;
  const size_t uv_plane = (size_t)uv_width * uv_height;

  const uint8_t *src_y = reader->data;
  const uint8_t *src_u = src_y + y_plane;
  const uint8_t *src_v = src_u + uv_plane;

  CopyPlane(image->planes[AOM_PLANE_Y], image->stride[AOM_PLANE_Y], src_y,
            width, height);
  CopyPlane(image->planes[AOM_PLANE_U], image->stride[AOM_PLANE_U], src_u,
            uv_width, uv_height);
  CopyPlane(image->planes[AOM_PLANE_V], image->stride[AOM_PLANE_V], src_v,
            uv_width, uv_height);

  reader->data += frame_size;
  reader->size -= frame_size;
  return true;
}

static void ApplyControls(aom_codec_ctx_t *codec, unsigned int usage,
                          uint8_t mode_flags, uint8_t cpu_used_raw,
                          uint8_t ctl0, uint8_t ctl1) {
  const int cpu_used = PickCpuUsed(usage, cpu_used_raw);
  const unsigned int lossless = (mode_flags >> 2) & 1;
  const unsigned int row_mt = (mode_flags >> 3) & 1;
  const unsigned int aq_mode = ctl0 % 4;
  const unsigned int deltaq_mode = ctl1 % 4;
  const unsigned int tile_columns = (ctl0 >> 4) & 0x3;
  const unsigned int tile_rows = (ctl1 >> 4) & 0x3;
  const unsigned int enable_cdef = (ctl0 >> 2) & 1;
  const unsigned int enable_restoration = (ctl1 >> 2) & 1;

  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AOME_SET_CPUUSED, cpu_used);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_LOSSLESS, lossless);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_ROW_MT, row_mt);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_AQ_MODE, aq_mode);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_DELTAQ_MODE,
                                      deltaq_mode);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_TILE_COLUMNS,
                                      tile_columns);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_TILE_ROWS, tile_rows);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_ENABLE_CDEF,
                                      enable_cdef);
  (void)AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1E_SET_ENABLE_RESTORATION,
                                      enable_restoration);
}

static bool EncodeFrame(aom_codec_ctx_t *codec, FuzzReader *reader,
                        unsigned int width, unsigned int height,
                        aom_codec_pts_t pts,
                        aom_enc_frame_flags_t flags) {
  aom_image_t image;
  memset(&image, 0, sizeof(image));

  if (!BuildImage(reader, width, height, &image)) {
    return false;
  }

  (void)aom_codec_encode(codec, &image, pts, 1, flags);
  DrainPackets(codec);

  aom_img_free(&image);
  return true;
}

__attribute__((constructor)) static void InitEncoderTemplates(void) {
  g_iface = aom_codec_av1_cx();
  if (g_iface == nullptr) return;

  const unsigned int usages[3] = { AOM_USAGE_GOOD_QUALITY, AOM_USAGE_REALTIME,
                                   AOM_USAGE_ALL_INTRA };
  for (unsigned int i = 0; i < 3; ++i) {
    g_have_template[i] =
        aom_codec_enc_config_default(g_iface, &g_cfg_templates[i], usages[i]) ==
        AOM_CODEC_OK;
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (g_iface == nullptr || size < kMinHeaderSize) return 0;

  FuzzReader reader = { data, size };
  const uint8_t mode_flags = ReadU8(&reader);
  const uint8_t cpu_used_raw = ReadU8(&reader);
  const uint8_t ctl0 = ReadU8(&reader);
  const uint8_t ctl1 = ReadU8(&reader);
  const unsigned int usage = PickUsage(mode_flags);
  const unsigned int width0 = PickDimension(ReadU16(&reader));
  const unsigned int height0 = PickDimension(ReadU16(&reader));
  const unsigned int bitrate = 1u + (ReadU16(&reader) % 4000u);
  const unsigned int width1 = PickDimension(ReadU16(&reader));
  const unsigned int height1 = PickDimension(ReadU16(&reader));
  const unsigned int threads0 = ReadU8(&reader) % 9;
  const unsigned int threads1 = ReadU8(&reader) % 9;

  aom_codec_enc_cfg_t cfg;
  if (!InitDefaultConfig(usage, &cfg)) return 0;

  cfg.g_usage = usage;
  cfg.g_w = width0;
  cfg.g_h = height0;
  cfg.g_threads = threads0;
  cfg.g_forced_max_frame_width = kMaxDimension;
  cfg.g_forced_max_frame_height = kMaxDimension;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 1000000;
  cfg.g_pass = AOM_RC_ONE_PASS;
  cfg.g_lag_in_frames = 0;
  cfg.g_error_resilient =
      (mode_flags & 0x80) ? AOM_ERROR_RESILIENT_DEFAULT : 0;
  cfg.rc_end_usage = PickRcMode(ctl0);
  cfg.rc_target_bitrate = bitrate;

  aom_codec_ctx_t codec;
  memset(&codec, 0, sizeof(codec));
  if (aom_codec_enc_init(&codec, g_iface, &cfg, 0) != AOM_CODEC_OK) return 0;

  ApplyControls(&codec, usage, mode_flags, cpu_used_raw, ctl0, ctl1);

  const aom_enc_frame_flags_t first_flags =
      (mode_flags & 0x20) ? AOM_EFLAG_FORCE_KF : 0;
  if (!EncodeFrame(&codec, &reader, width0, height0, 0, first_flags)) {
    (void)aom_codec_destroy(&codec);
    return 0;
  }

  if (mode_flags & 0x10) {
    cfg.g_w = width1;
    cfg.g_h = height1;
    cfg.g_threads = threads1;
    cfg.rc_end_usage = PickRcMode(ctl1);
    if (aom_codec_enc_config_set(&codec, &cfg) == AOM_CODEC_OK) {
      const aom_enc_frame_flags_t second_flags =
          (mode_flags & 0x40) ? AOM_EFLAG_FORCE_KF : 0;
      (void)EncodeFrame(&codec, &reader, width1, height1, 1, second_flags);
    }
  }

  for (int flush_round = 0; flush_round < 8; ++flush_round) {
    if (aom_codec_encode(&codec, nullptr, 0, 0, 0) != AOM_CODEC_OK) break;
    aom_codec_iter_t iter = nullptr;
    bool got_packet = false;
    while (aom_codec_get_cx_data(&codec, &iter) != nullptr) {
      got_packet = true;
    }
    if (!got_packet) break;
  }

  (void)aom_codec_destroy(&codec);
  return 0;
}

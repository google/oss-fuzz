// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "exr_proto_converter.h"

static void WriteInt(std::stringstream &out, uint32_t x) {
  //x = __builtin_bswap32(x);
  out.write((char *)&x, sizeof(x));
}

static void WriteLong(std::stringstream &out, uint64_t x) {
  //x = __builtin_bswap64(x);
  out.write((char *)&x, sizeof(x));
}

static void WriteFloat(std::stringstream &out, float x) {
  out.write((char *)&x, sizeof(x));
}

static void WriteByte(std::stringstream &out, uint8_t x) {
  out.write((char *)&x, sizeof(x));
}

static void WriteString(std::stringstream &out, std::string x) {
  out.write(x.data(), x.size());
  out.write("\x00", 1);
}

static void WriteNString(std::stringstream &out, std::string x) {
  out.write(x.data(), x.size());
}

static void WriteTypeInfo(std::stringstream &out, std::string name, std::string type, int size) {
  WriteString(out, name);
  WriteString(out, type);
  WriteInt(out, size);
}

static int CalculateChannelSize (int chan_type) {
  int size = 0;
  switch (chan_type % 3) {
    case 1:
      size = 2;
      break;
    default:
      size = 4;
  }
  return size;
}

const float MIN_PIXEL_ASPECT_RATIO = 1e-6f;
const float MAX_PIXEL_ASPECT_RATIO = 1e+6f;

std::string ProtoToExr(const ExrProto &exr_proto) {
  std::stringstream all;
  const unsigned char magic[] = {0x76, 0x2f, 0x31, 0x01};
  all.write((const char*)magic, sizeof(magic));

  // we only support version2 in single flat scanlines for now
  const unsigned char version[] = {0x02, 0x00, 0x00, 0x00};
  all.write((const char*)version, sizeof(version));

  auto &header = exr_proto.header();

  std::stringstream channels;
  std::unordered_set<std::string> used_channels;
  int pixel_data_size = 0;
  for (const auto& chan : header.channel_list().channels()) {
    std::string chname = "G";
    if (!chan.chname().empty() && std::isprint(static_cast<unsigned char>(chan.chname()[0]))) { 
      chname = chan.chname();
    }
    if (used_channels.find(chname) != used_channels.end()) {
      continue; // we don't care about this one. bad but at least works
    } else {
      used_channels.insert(chname);
    }
    WriteString(channels, chname);

    WriteInt(channels, chan.pixel_type() % 3); // UINT, HALF, FLOAT
    WriteByte(channels, chan.plinear() % 2); // 0 or 1
    WriteByte(channels, 0);
    WriteByte(channels, 0);
    WriteByte(channels, 0);
    WriteInt(channels, std::max(chan.xsampling(), 1));
    WriteInt(channels, std::max(chan.ysampling(), 1));

    pixel_data_size += CalculateChannelSize(chan.pixel_type());
  }
  WriteTypeInfo(all, "channels", "chlist", channels.str().size() + 1);
  WriteString(all, channels.str()); // value

  WriteTypeInfo(all, "compression", "compression", 1);
  WriteByte(all, header.compression().compression() % 10); //value

  // this is the base point
  auto xmin = header.datawindow().xmin();
  auto ymin = header.datawindow().ymin();

  // this are the lenght of the sides (h and w) so we compute the other coordinates
  auto xmax = xmin + std::max(std::min(header.datawindow().w(), 0), 20);
  auto ymax = ymin + std::max(std::min(header.datawindow().h(), 0), 20);

  WriteTypeInfo(all, "dataWindow", "box2i", 16);
  WriteInt(all, xmin);
  WriteInt(all, ymin);
  WriteInt(all, xmax);
  WriteInt(all, ymax);

  // we are copying datawindow values to decrease the number of operations
  // but this also reduce the fuzzed testcases
  WriteTypeInfo(all, "displayWindow", "box2i", 16);
  WriteInt(all, xmin);
  WriteInt(all, ymin);
  WriteInt(all, xmax);
  WriteInt(all, ymax);

  WriteTypeInfo(all, "lineOrder", "lineOrder", 1);
  WriteByte(all, header.lineorder().lineorder() % 3);

  WriteTypeInfo(all, "pixelAspectRatio", "float", 4);
  auto par = std::max(MIN_PIXEL_ASPECT_RATIO, std::min(header.pixelaspectratio(), MAX_PIXEL_ASPECT_RATIO));
  if (par == 0.0) { par += 0.1337; }
  WriteFloat(all, par);

  WriteTypeInfo(all, "screenWindowCenter", "v2f", 8);
  WriteFloat(all, header.screenwindowcenter().f1());
  WriteFloat(all, header.screenwindowcenter().f2());

  WriteTypeInfo(all, "screenWindowWidth", "float", 4);
  WriteFloat(all, header.screenwindowwidth());

  // end of header
  WriteByte(all, 0);

  auto n_channels = header.channel_list().channels_size();
  auto lines = (xmax - xmin);
  auto n_pixels = (ymax - ymin);

  pixel_data_size = pixel_data_size * n_pixels;

  // base_offset contains the header size and the offset table size
  // the offset table contains 64bit integers for every scanline
  auto base_offset = static_cast<int>(all.tellp()) + (lines * 8);

  std::stringstream offset_table;
  std::stringstream scanlines;

  for (int i = 0; i<= lines; i++) {
    // write the offset for the current line
    // (4 + 4 + n_pixels * n_channels) for every scanline
    WriteInt(offset_table, base_offset + (i * (8 + pixel_data_size)));

    // write scanline number
    WriteInt(scanlines, i);
    // write pixel data size times pixel number
    WriteInt(scanlines, pixel_data_size);

    // write the pixel data
    for (const auto& chan : header.channel_list().channels()) {
      std::string pixels(n_pixels * CalculateChannelSize(chan.pixel_type()), '\xea');
      pixels.replace(0, exr_proto.scanlines().size(), exr_proto.scanlines());
      WriteNString(scanlines, pixels);
    }
  }

  WriteNString(all, offset_table.str());
  WriteByte(all, 255);
  WriteNString(all, scanlines.str());

  std::string res = all.str();
  if (const char *dump_path = getenv("PROTO_FUZZER_DUMP_PATH")) {
    // With libFuzzer binary run this to generate a EXR file x.exr:
    // PROTO_FUZZER_DUMP_PATH=x.exr ./a.out proto-input
    std::ofstream of(dump_path, std::ios::binary);
    of.write(res.data(), res.size());
  }
  return res;
}

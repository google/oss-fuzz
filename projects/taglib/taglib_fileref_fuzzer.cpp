// Copyright 2026 Google LLC
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

// Fuzzes TagLib's generic file type detection and tag/audio-property parsing
// over all supported formats (MP3/ID3v2, FLAC, OGG/Vorbis/Opus/Speex, MP4/AAC,
// WAV, AIFF, APE, MPC, WavPack, DSF, DSDIFF, tracker formats, ...).

#include <cstddef>
#include <cstdint>

#include <audioproperties.h>
#include <fileref.h>
#include <tag.h>
#include <tbytevector.h>
#include <tbytevectorstream.h>
#include <tpropertymap.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const TagLib::ByteVector input(reinterpret_cast<const char *>(data),
                                 static_cast<unsigned int>(size));
  TagLib::ByteVectorStream stream(input);
  {
    TagLib::FileRef ref(&stream, /*readAudioProperties=*/true,
                        TagLib::AudioProperties::Average);
    if (!ref.isNull()) {
      if (ref.tag()) {
        const TagLib::Tag *tag = ref.tag();
        // Touch the standard fields to force a full tag parse.
        (void)tag->title();
        (void)tag->artist();
        (void)tag->album();
        (void)tag->comment();
        (void)tag->genre();
        (void)tag->year();
        (void)tag->track();
        (void)tag->properties();
      }
      // Parse embedded pictures and other complex properties.
      (void)ref.complexProperties("PICTURE");
      if (ref.audioProperties()) {
        const TagLib::AudioProperties *props = ref.audioProperties();
        (void)props->lengthInSeconds();
        (void)props->lengthInMilliseconds();
        (void)props->bitrate();
        (void)props->sampleRate();
        (void)props->channels();
      }
    }
  }  // FileRef is destroyed before the stream it borrows.
  return 0;
}

/*
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdio.h>
#include <stdlib.h>

#include <libass/ass.h>

static ASS_Library *ass_library;
static ASS_Renderer *ass_renderer;

void msg_callback(int level, const char *fmt, va_list va, void *data) {
}

static const int kFrameWidth = 1280;
static const int kFrameHeight = 720;

struct init {
  init(int frame_w, int frame_h) {
    ass_library = ass_library_init();
    if (!ass_library) {
      printf("ass_library_init failed!\n");
      exit(1);
    }

    ass_set_message_cb(ass_library, msg_callback, NULL);

    ass_renderer = ass_renderer_init(ass_library);
    if (!ass_renderer) {
      printf("ass_renderer_init failed!\n");
      exit(1);
    }

    ass_set_frame_size(ass_renderer, frame_w, frame_h);
    ass_set_fonts(ass_renderer, nullptr, "sans-serif",
                  ASS_FONTPROVIDER_AUTODETECT, nullptr, 1);
  }

  ~init() {
    ass_renderer_done(ass_renderer);
    ass_library_done(ass_library);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static init initialized(kFrameWidth, kFrameHeight);

  ASS_Track *track = ass_read_memory(ass_library, (char *)data, size, nullptr);
  if (!track) return 0;

  for (int i = 0; i < track->n_events; ++i) {
    ASS_Event &ev = track->events[i];
    long long tm = ev.Start + ev.Duration / 2;
    ass_render_frame(ass_renderer, track, tm, nullptr);
  }
  ass_free_track(track);
  return 0;
}

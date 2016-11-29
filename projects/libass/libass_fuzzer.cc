#include <stdio.h>
#include <stdlib.h>

#include <libass/ass.h>

static ASS_Library *ass_library;
static ASS_Renderer *ass_renderer;

void msg_callback(int level, const char *fmt, va_list va, void *data) {
}

static const int kFrameWidth = 1280;
static const int kFrameHeight = 720;

static bool init(int frame_w, int frame_h) {
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
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool initialized = init(kFrameWidth, kFrameHeight);

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

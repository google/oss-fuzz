// Copyright 2016 Google Inc.
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

#include "libtsm.h"

#define WIDTH 80
#define HEIGHT 24

static void terminal_write_fn(struct tsm_vte *vte,
			      const char *u8,
			      size_t len,
			      void *data)
{
  // try to access the written data
  static char out[4096];
  while (len--)
    out[len % sizeof(out)] = u8[len];
}

static int term_draw_cell(struct tsm_screen *screen, uint64_t id,
                          const uint32_t *ch, size_t len,
                          unsigned int cwidth, unsigned int posx,
                          unsigned int posy,
                          const struct tsm_screen_attr *attr,
                          tsm_age_t age, void *data)
{
  if (posx >= WIDTH || posy >= HEIGHT)
    abort();
  return 0;
}

// Entry point for LibFuzzer.
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  struct tsm_screen *screen;
  struct tsm_vte *vte;
  const int scrollback_size = 200;  // frecon use 200

  tsm_screen_new(&screen, NULL, NULL);
  tsm_screen_set_max_sb(screen, scrollback_size);
  tsm_vte_new(&vte, screen, terminal_write_fn, NULL, NULL, NULL);
  tsm_screen_resize(screen, WIDTH, HEIGHT);

  tsm_vte_input(vte, (const char*) data, size);
  tsm_screen_draw(screen, term_draw_cell, NULL);

  tsm_vte_unref(vte);
  tsm_screen_unref(screen);
  return 0;
}

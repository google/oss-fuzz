/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Fuzz ANSI/VT100 terminal escape sequence parsing.
 *
 * Terminal emulators like GNU Screen must parse a rich set of escape
 * sequences for cursor control, color, scrolling, and more. This is
 * a common source of memory corruption bugs.
 *
 * Sequences parsed:
 *   ESC [ <params> <intermediate> <final>   (CSI sequences)
 *   ESC ] <string> ST                       (OSC sequences)
 *   ESC <intermediate> <final>              (simple escapes)
 *   C0 control characters (BEL, BS, TAB, LF, CR, etc.)
 *   C1 control characters (8-bit: 0x80-0x9F)
 *
 * The parser maintains a virtual terminal state with cursor position,
 * scroll region, character attributes, and a character buffer.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TERM_COLS 80
#define TERM_ROWS 24
#define MAX_CSI_PARAMS 16
#define MAX_OSC_LEN 256

typedef struct {
  int bold;
  int underline;
  int reverse;
  int blink;
  int invisible;
  int fg_color; /* 0-255 */
  int bg_color; /* 0-255 */
} CharAttrs;

typedef struct {
  char cells[TERM_ROWS][TERM_COLS];
  CharAttrs attrs[TERM_ROWS][TERM_COLS];
  int cursor_x, cursor_y;
  int scroll_top, scroll_bottom;
  int saved_x, saved_y;
  CharAttrs current_attr;
  int insert_mode;
  int origin_mode;
  int autowrap;
  int charset_g0, charset_g1;
  char title[MAX_OSC_LEN];
} VTerm;

static void vterm_init(VTerm *t) {
  memset(t, 0, sizeof(*t));
  t->scroll_bottom = TERM_ROWS - 1;
  t->autowrap = 1;
  t->current_attr.fg_color = 7;
  t->current_attr.bg_color = 0;
  for (int r = 0; r < TERM_ROWS; r++)
    memset(t->cells[r], ' ', TERM_COLS);
}

static void vterm_scroll_up(VTerm *t) {
  if (t->scroll_top < 0 || t->scroll_top >= TERM_ROWS)
    return;
  if (t->scroll_bottom < 0 || t->scroll_bottom >= TERM_ROWS)
    return;
  for (int r = t->scroll_top; r < t->scroll_bottom; r++) {
    memcpy(t->cells[r], t->cells[r + 1], TERM_COLS);
    memcpy(&t->attrs[r], &t->attrs[r + 1], sizeof(CharAttrs) * TERM_COLS);
  }
  memset(t->cells[t->scroll_bottom], ' ', TERM_COLS);
  memset(&t->attrs[t->scroll_bottom], 0, sizeof(CharAttrs) * TERM_COLS);
}

static void vterm_scroll_down(VTerm *t) {
  if (t->scroll_top < 0 || t->scroll_top >= TERM_ROWS)
    return;
  if (t->scroll_bottom < 0 || t->scroll_bottom >= TERM_ROWS)
    return;
  for (int r = t->scroll_bottom; r > t->scroll_top; r--) {
    memcpy(t->cells[r], t->cells[r - 1], TERM_COLS);
    memcpy(&t->attrs[r], &t->attrs[r - 1], sizeof(CharAttrs) * TERM_COLS);
  }
  memset(t->cells[t->scroll_top], ' ', TERM_COLS);
  memset(&t->attrs[t->scroll_top], 0, sizeof(CharAttrs) * TERM_COLS);
}

static void vterm_newline(VTerm *t) {
  t->cursor_y++;
  if (t->cursor_y > t->scroll_bottom) {
    t->cursor_y = t->scroll_bottom;
    vterm_scroll_up(t);
  }
}

static void vterm_put_char(VTerm *t, char c) {
  if (t->cursor_x >= 0 && t->cursor_x < TERM_COLS && t->cursor_y >= 0 &&
      t->cursor_y < TERM_ROWS) {
    if (t->insert_mode) {
      /* Shift characters right */
      for (int x = TERM_COLS - 1; x > t->cursor_x; x--) {
        t->cells[t->cursor_y][x] = t->cells[t->cursor_y][x - 1];
        t->attrs[t->cursor_y][x] = t->attrs[t->cursor_y][x - 1];
      }
    }
    t->cells[t->cursor_y][t->cursor_x] = c;
    t->attrs[t->cursor_y][t->cursor_x] = t->current_attr;
  }
  t->cursor_x++;
  if (t->cursor_x >= TERM_COLS) {
    if (t->autowrap) {
      t->cursor_x = 0;
      vterm_newline(t);
    } else {
      t->cursor_x = TERM_COLS - 1;
    }
  }
}

/* Clamp helper */
static int clamp(int val, int lo, int hi) {
  if (val < lo) return lo;
  if (val > hi) return hi;
  return val;
}

/* Process SGR (Select Graphic Rendition) parameters */
static void process_sgr(VTerm *t, int *params, int nparams) {
  for (int i = 0; i < nparams; i++) {
    int p = params[i];
    if (p == 0) {
      memset(&t->current_attr, 0, sizeof(t->current_attr));
      t->current_attr.fg_color = 7;
    } else if (p == 1)
      t->current_attr.bold = 1;
    else if (p == 4)
      t->current_attr.underline = 1;
    else if (p == 5)
      t->current_attr.blink = 1;
    else if (p == 7)
      t->current_attr.reverse = 1;
    else if (p == 8)
      t->current_attr.invisible = 1;
    else if (p == 22)
      t->current_attr.bold = 0;
    else if (p == 24)
      t->current_attr.underline = 0;
    else if (p == 25)
      t->current_attr.blink = 0;
    else if (p == 27)
      t->current_attr.reverse = 0;
    else if (p == 28)
      t->current_attr.invisible = 0;
    else if (p >= 30 && p <= 37)
      t->current_attr.fg_color = p - 30;
    else if (p == 38 && i + 2 < nparams && params[i + 1] == 5) {
      t->current_attr.fg_color = params[i + 2];
      i += 2;
    } else if (p == 39)
      t->current_attr.fg_color = 7;
    else if (p >= 40 && p <= 47)
      t->current_attr.bg_color = p - 40;
    else if (p == 48 && i + 2 < nparams && params[i + 1] == 5) {
      t->current_attr.bg_color = params[i + 2];
      i += 2;
    } else if (p == 49)
      t->current_attr.bg_color = 0;
    else if (p >= 90 && p <= 97)
      t->current_attr.fg_color = p - 90 + 8;
    else if (p >= 100 && p <= 107)
      t->current_attr.bg_color = p - 100 + 8;
  }
}

/* Process a CSI sequence: ESC [ params final */
static void process_csi(VTerm *t, int *params, int nparams,
                        char intermediate, char final_ch) {
  int p1 = nparams > 0 ? params[0] : 0;
  int p2 = nparams > 1 ? params[1] : 0;

  /* Handle '?' private mode */
  if (intermediate == '?') {
    /* DECSET/DECRST */
    switch (final_ch) {
    case 'h': /* Set private mode */
      if (p1 == 6)
        t->origin_mode = 1;
      else if (p1 == 7)
        t->autowrap = 1;
      break;
    case 'l': /* Reset private mode */
      if (p1 == 6)
        t->origin_mode = 0;
      else if (p1 == 7)
        t->autowrap = 0;
      break;
    }
    return;
  }

  switch (final_ch) {
  case 'A': /* CUU - Cursor Up */
    t->cursor_y = clamp(t->cursor_y - (p1 ? p1 : 1), 0, TERM_ROWS - 1);
    break;
  case 'B': /* CUD - Cursor Down */
    t->cursor_y = clamp(t->cursor_y + (p1 ? p1 : 1), 0, TERM_ROWS - 1);
    break;
  case 'C': /* CUF - Cursor Forward */
    t->cursor_x = clamp(t->cursor_x + (p1 ? p1 : 1), 0, TERM_COLS - 1);
    break;
  case 'D': /* CUB - Cursor Backward */
    t->cursor_x = clamp(t->cursor_x - (p1 ? p1 : 1), 0, TERM_COLS - 1);
    break;
  case 'E': /* CNL - Cursor Next Line */
    t->cursor_x = 0;
    t->cursor_y = clamp(t->cursor_y + (p1 ? p1 : 1), 0, TERM_ROWS - 1);
    break;
  case 'F': /* CPL - Cursor Previous Line */
    t->cursor_x = 0;
    t->cursor_y = clamp(t->cursor_y - (p1 ? p1 : 1), 0, TERM_ROWS - 1);
    break;
  case 'G': /* CHA - Cursor Horizontal Absolute */
    t->cursor_x = clamp((p1 ? p1 : 1) - 1, 0, TERM_COLS - 1);
    break;
  case 'H': /* CUP - Cursor Position */
  case 'f': /* HVP - Horizontal Vertical Position */
    t->cursor_y = clamp((p1 ? p1 : 1) - 1, 0, TERM_ROWS - 1);
    t->cursor_x = clamp((p2 ? p2 : 1) - 1, 0, TERM_COLS - 1);
    break;
  case 'J': /* ED - Erase in Display */
    if (p1 == 0) {
      /* Clear from cursor to end */
      if (t->cursor_y >= 0 && t->cursor_y < TERM_ROWS) {
        for (int x = t->cursor_x; x < TERM_COLS; x++)
          t->cells[t->cursor_y][x] = ' ';
        for (int r = t->cursor_y + 1; r < TERM_ROWS; r++)
          memset(t->cells[r], ' ', TERM_COLS);
      }
    } else if (p1 == 1) {
      /* Clear from start to cursor */
      for (int r = 0; r < t->cursor_y && r < TERM_ROWS; r++)
        memset(t->cells[r], ' ', TERM_COLS);
      if (t->cursor_y >= 0 && t->cursor_y < TERM_ROWS)
        for (int x = 0; x <= t->cursor_x && x < TERM_COLS; x++)
          t->cells[t->cursor_y][x] = ' ';
    } else if (p1 == 2) {
      /* Clear entire display */
      for (int r = 0; r < TERM_ROWS; r++)
        memset(t->cells[r], ' ', TERM_COLS);
    }
    break;
  case 'K': /* EL - Erase in Line */
    if (t->cursor_y < 0 || t->cursor_y >= TERM_ROWS)
      break;
    if (p1 == 0) {
      for (int x = t->cursor_x; x < TERM_COLS; x++)
        t->cells[t->cursor_y][x] = ' ';
    } else if (p1 == 1) {
      for (int x = 0; x <= t->cursor_x && x < TERM_COLS; x++)
        t->cells[t->cursor_y][x] = ' ';
    } else if (p1 == 2) {
      memset(t->cells[t->cursor_y], ' ', TERM_COLS);
    }
    break;
  case 'L': /* IL - Insert Lines */
    for (int n = 0; n < (p1 ? p1 : 1); n++)
      vterm_scroll_down(t);
    break;
  case 'M': /* DL - Delete Lines */
    for (int n = 0; n < (p1 ? p1 : 1); n++)
      vterm_scroll_up(t);
    break;
  case 'P': /* DCH - Delete Character */
    if (t->cursor_y >= 0 && t->cursor_y < TERM_ROWS) {
      int count = p1 ? p1 : 1;
      for (int x = t->cursor_x; x + count < TERM_COLS; x++)
        t->cells[t->cursor_y][x] = t->cells[t->cursor_y][x + count];
    }
    break;
  case 'S': /* SU - Scroll Up */
    for (int n = 0; n < (p1 ? p1 : 1); n++)
      vterm_scroll_up(t);
    break;
  case 'T': /* SD - Scroll Down */
    for (int n = 0; n < (p1 ? p1 : 1); n++)
      vterm_scroll_down(t);
    break;
  case 'd': /* VPA - Vertical Position Absolute */
    t->cursor_y = clamp((p1 ? p1 : 1) - 1, 0, TERM_ROWS - 1);
    break;
  case 'h': /* SM - Set Mode */
    if (p1 == 4)
      t->insert_mode = 1;
    break;
  case 'l': /* RM - Reset Mode */
    if (p1 == 4)
      t->insert_mode = 0;
    break;
  case 'm': /* SGR - Select Graphic Rendition */
    if (nparams == 0) {
      int zero = 0;
      process_sgr(t, &zero, 1);
    } else {
      process_sgr(t, params, nparams);
    }
    break;
  case 'r': /* DECSTBM - Set Scrolling Region */
    t->scroll_top = clamp((p1 ? p1 : 1) - 1, 0, TERM_ROWS - 1);
    t->scroll_bottom = clamp((p2 ? p2 : TERM_ROWS) - 1, 0, TERM_ROWS - 1);
    if (t->scroll_top > t->scroll_bottom) {
      int tmp = t->scroll_top;
      t->scroll_top = t->scroll_bottom;
      t->scroll_bottom = tmp;
    }
    t->cursor_x = 0;
    t->cursor_y = t->origin_mode ? t->scroll_top : 0;
    break;
  case 's': /* SCP - Save Cursor Position */
    t->saved_x = t->cursor_x;
    t->saved_y = t->cursor_y;
    break;
  case 'u': /* RCP - Restore Cursor Position */
    t->cursor_x = clamp(t->saved_x, 0, TERM_COLS - 1);
    t->cursor_y = clamp(t->saved_y, 0, TERM_ROWS - 1);
    break;
  case '@': /* ICH - Insert Characters */
    if (t->cursor_y >= 0 && t->cursor_y < TERM_ROWS) {
      int count = p1 ? p1 : 1;
      for (int x = TERM_COLS - 1; x >= t->cursor_x + count; x--)
        t->cells[t->cursor_y][x] = t->cells[t->cursor_y][x - count];
      for (int x = t->cursor_x;
           x < t->cursor_x + count && x < TERM_COLS; x++)
        t->cells[t->cursor_y][x] = ' ';
    }
    break;
  case 'X': /* ECH - Erase Characters */
    if (t->cursor_y >= 0 && t->cursor_y < TERM_ROWS) {
      int count = p1 ? p1 : 1;
      for (int x = t->cursor_x;
           x < t->cursor_x + count && x < TERM_COLS; x++)
        t->cells[t->cursor_y][x] = ' ';
    }
    break;
  }
}

/* Main parsing function */
static void vterm_process(VTerm *t, const uint8_t *data, size_t len) {
  size_t i = 0;

  while (i < len) {
    uint8_t c = data[i];

    if (c == 0x1B) { /* ESC */
      i++;
      if (i >= len)
        break;

      c = data[i];

      if (c == '[') {
        /* CSI sequence: ESC [ */
        i++;
        int params[MAX_CSI_PARAMS];
        int nparams = 0;
        char intermediate = 0;

        /* Check for private mode indicator */
        if (i < len && (data[i] == '?' || data[i] == '>' || data[i] == '!')) {
          intermediate = data[i];
          i++;
        }

        /* Parse numeric parameters */
        while (i < len && nparams < MAX_CSI_PARAMS) {
          if (data[i] >= '0' && data[i] <= '9') {
            int val = 0;
            while (i < len && data[i] >= '0' && data[i] <= '9') {
              val = val * 10 + (data[i] - '0');
              if (val > 9999)
                val = 9999;
              i++;
            }
            params[nparams++] = val;
          } else if (data[i] == ';') {
            if (nparams == 0)
              params[nparams++] = 0;
            i++;
          } else {
            break;
          }
        }

        /* Check for intermediate bytes */
        while (i < len && data[i] >= 0x20 && data[i] <= 0x2F) {
          if (!intermediate)
            intermediate = data[i];
          i++;
        }

        /* Final byte */
        if (i < len && data[i] >= 0x40 && data[i] <= 0x7E) {
          process_csi(t, params, nparams, intermediate, data[i]);
          i++;
        }
      } else if (c == ']') {
        /* OSC sequence: ESC ] ... ST/BEL */
        i++;
        char osc_buf[MAX_OSC_LEN];
        int osc_len = 0;

        while (i < len && osc_len < MAX_OSC_LEN - 1) {
          if (data[i] == 0x07) { /* BEL terminates OSC */
            i++;
            break;
          }
          if (data[i] == 0x1B && i + 1 < len && data[i + 1] == '\\') {
            /* ST (ESC \) terminates OSC */
            i += 2;
            break;
          }
          osc_buf[osc_len++] = data[i++];
        }
        osc_buf[osc_len] = '\0';

        /* Parse OSC: Ps ; Pt  where Ps is the type number */
        if (osc_len > 0) {
          int osc_type = 0;
          int j = 0;
          while (j < osc_len && osc_buf[j] >= '0' && osc_buf[j] <= '9') {
            osc_type = osc_type * 10 + (osc_buf[j] - '0');
            j++;
          }
          if (j < osc_len && osc_buf[j] == ';')
            j++;

          if (osc_type == 0 || osc_type == 2) {
            /* Set window title */
            int tlen = osc_len - j;
            if (tlen >= MAX_OSC_LEN)
              tlen = MAX_OSC_LEN - 1;
            if (tlen > 0)
              memcpy(t->title, osc_buf + j, tlen);
            t->title[tlen] = '\0';
          }
        }
      } else if (c == 'D') { /* IND - Index (move down) */
        vterm_newline(t);
        i++;
      } else if (c == 'M') { /* RI - Reverse Index (move up) */
        t->cursor_y--;
        if (t->cursor_y < t->scroll_top) {
          t->cursor_y = t->scroll_top;
          vterm_scroll_down(t);
        }
        i++;
      } else if (c == 'E') { /* NEL - Next Line */
        t->cursor_x = 0;
        vterm_newline(t);
        i++;
      } else if (c == '7') { /* DECSC - Save Cursor */
        t->saved_x = t->cursor_x;
        t->saved_y = t->cursor_y;
        i++;
      } else if (c == '8') { /* DECRC - Restore Cursor */
        t->cursor_x = clamp(t->saved_x, 0, TERM_COLS - 1);
        t->cursor_y = clamp(t->saved_y, 0, TERM_ROWS - 1);
        i++;
      } else if (c == 'c') { /* RIS - Full Reset */
        vterm_init(t);
        i++;
      } else if (c == '(' || c == ')') { /* Designate Character Set */
        i++;
        if (i < len) {
          if (c == '(')
            t->charset_g0 = data[i];
          else
            t->charset_g1 = data[i];
          i++;
        }
      } else if (c == '#') { /* DEC line attributes */
        i++;
        if (i < len)
          i++; /* skip the attribute byte */
      } else {
        i++; /* skip unknown escape */
      }
    } else if (c < 0x20) {
      /* C0 control characters */
      switch (c) {
      case 0x07: /* BEL */
        break;
      case 0x08: /* BS - Backspace */
        if (t->cursor_x > 0)
          t->cursor_x--;
        break;
      case 0x09: /* HT - Tab */
        t->cursor_x = (t->cursor_x + 8) & ~7;
        if (t->cursor_x >= TERM_COLS)
          t->cursor_x = TERM_COLS - 1;
        break;
      case 0x0A: /* LF - Line Feed */
      case 0x0B: /* VT - Vertical Tab */
      case 0x0C: /* FF - Form Feed */
        vterm_newline(t);
        break;
      case 0x0D: /* CR - Carriage Return */
        t->cursor_x = 0;
        break;
      case 0x0E: /* SO - Shift Out (select G1) */
        break;
      case 0x0F: /* SI - Shift In (select G0) */
        break;
      }
      i++;
    } else if (c >= 0x80 && c <= 0x9F) {
      /* C1 control characters (8-bit) */
      if (c == 0x84) /* IND */
        vterm_newline(t);
      else if (c == 0x85) { /* NEL */
        t->cursor_x = 0;
        vterm_newline(t);
      } else if (c == 0x8D) { /* RI */
        t->cursor_y--;
        if (t->cursor_y < t->scroll_top) {
          t->cursor_y = t->scroll_top;
          vterm_scroll_down(t);
        }
      } else if (c == 0x9B) {
        /* CSI via 8-bit C1: same as ESC [ */
        i++;
        int params[MAX_CSI_PARAMS];
        int nparams = 0;
        char intermediate = 0;

        if (i < len && (data[i] == '?' || data[i] == '>')) {
          intermediate = data[i];
          i++;
        }

        while (i < len && nparams < MAX_CSI_PARAMS) {
          if (data[i] >= '0' && data[i] <= '9') {
            int val = 0;
            while (i < len && data[i] >= '0' && data[i] <= '9') {
              val = val * 10 + (data[i] - '0');
              if (val > 9999)
                val = 9999;
              i++;
            }
            params[nparams++] = val;
          } else if (data[i] == ';') {
            if (nparams == 0)
              params[nparams++] = 0;
            i++;
          } else {
            break;
          }
        }

        if (i < len && data[i] >= 0x40 && data[i] <= 0x7E) {
          process_csi(t, params, nparams, intermediate, data[i]);
          i++;
        }
        continue;
      }
      i++;
    } else {
      /* Printable character */
      vterm_put_char(t, (char)c);
      i++;
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 65536)
    return 0;

  VTerm term;
  vterm_init(&term);
  vterm_process(&term, data, size);

  return 0;
}

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
 * Fuzz GNU Screen's command/escape key binding parser.
 *
 * Screen has its own escape mechanism (default Ctrl-A) followed by
 * a command character. This fuzzer parses screen-style command strings
 * that might appear in .screenrc configuration or be typed interactively.
 *
 * Commands parsed:
 *   - Window management: screen, select, next, prev, other
 *   - Split/layout: split, focus, remove, only, layout
 *   - Copy/paste: copy, paste, scrollback
 *   - Terminal: hardcopy, log, monitor, silence
 *   - Session: detach, quit, sessionname
 *   - Settings: escape, bindkey, termcapinfo, caption, hardstatus
 *   - Misc: stuff, exec, colon, title, shelltitle
 *
 * The parser handles screen command syntax:
 *   command [args...]
 *   bind key command [args...]
 *   escape xy (where x=command char, y=literal char)
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CMD_LEN 256
#define MAX_ARGS 16
#define MAX_ARG_LEN 256
#define MAX_BINDINGS 128

typedef struct {
  char name[MAX_CMD_LEN];
  char args[MAX_ARGS][MAX_ARG_LEN];
  int num_args;
} ScreenCommand;

typedef struct {
  char key[16];
  ScreenCommand cmd;
} KeyBinding;

typedef struct {
  char escape_char;
  char literal_char;
  KeyBinding bindings[MAX_BINDINGS];
  int num_bindings;
  char session_name[MAX_CMD_LEN];
  char shell_title[MAX_CMD_LEN];
  char caption[MAX_CMD_LEN];
  char hardstatus[MAX_CMD_LEN];
  int scroll_back_size;
  int visual_bell;
  int auto_detach;
  int start_message;
  int verbose;
} ScreenConfig;

static void config_init(ScreenConfig *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->escape_char = '\001'; /* Ctrl-A */
  cfg->literal_char = 'a';
  cfg->scroll_back_size = 100;
  cfg->auto_detach = 1;
}

/* Skip whitespace */
static const char *skip_ws(const char *s, const char *end) {
  while (s < end && (*s == ' ' || *s == '\t'))
    s++;
  return s;
}

/* Parse a single token (word or quoted string) */
static const char *parse_token(const char *s, const char *end, char *out,
                               size_t out_max) {
  size_t pos = 0;
  s = skip_ws(s, end);

  if (s >= end) {
    out[0] = '\0';
    return s;
  }

  if (*s == '"') {
    /* Quoted string */
    s++;
    while (s < end && *s != '"' && pos < out_max - 1) {
      if (*s == '\\' && s + 1 < end) {
        s++;
        switch (*s) {
        case 'n':
          out[pos++] = '\n';
          break;
        case 'r':
          out[pos++] = '\r';
          break;
        case 't':
          out[pos++] = '\t';
          break;
        case '\\':
          out[pos++] = '\\';
          break;
        case '"':
          out[pos++] = '"';
          break;
        case '0':
        case '1':
        case '2':
        case '3': {
          /* Octal escape */
          int val = *s - '0';
          if (s + 1 < end && s[1] >= '0' && s[1] <= '7') {
            s++;
            val = val * 8 + (*s - '0');
          }
          if (s + 1 < end && s[1] >= '0' && s[1] <= '7') {
            s++;
            val = val * 8 + (*s - '0');
          }
          out[pos++] = (char)val;
          break;
        }
        default:
          out[pos++] = *s;
          break;
        }
      } else {
        out[pos++] = *s;
      }
      s++;
    }
    if (s < end && *s == '"')
      s++;
  } else if (*s == '\'') {
    /* Single-quoted string (no escapes) */
    s++;
    while (s < end && *s != '\'' && pos < out_max - 1)
      out[pos++] = *s++;
    if (s < end && *s == '\'')
      s++;
  } else {
    /* Unquoted word */
    while (s < end && *s != ' ' && *s != '\t' && *s != '\n' && *s != '#' &&
           pos < out_max - 1)
      out[pos++] = *s++;
  }

  out[pos] = '\0';
  return s;
}

/* Case-insensitive string comparison */
static int str_eq_nocase(const char *a, const char *b) {
  while (*a && *b) {
    char ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z')
      ca += 32;
    if (cb >= 'A' && cb <= 'Z')
      cb += 32;
    if (ca != cb)
      return 0;
    a++;
    b++;
  }
  return *a == *b;
}

/* Parse and interpret a single screen command */
static void process_command(ScreenConfig *cfg, ScreenCommand *cmd) {
  if (cmd->name[0] == '\0')
    return;

  if (str_eq_nocase(cmd->name, "escape") && cmd->num_args >= 1) {
    if (strlen(cmd->args[0]) >= 2) {
      cfg->escape_char = cmd->args[0][0];
      cfg->literal_char = cmd->args[0][1];
    }
  } else if (str_eq_nocase(cmd->name, "bind") && cmd->num_args >= 2) {
    if (cfg->num_bindings < MAX_BINDINGS) {
      KeyBinding *b = &cfg->bindings[cfg->num_bindings];
      strncpy(b->key, cmd->args[0], sizeof(b->key) - 1);
      strncpy(b->cmd.name, cmd->args[1], MAX_CMD_LEN - 1);
      b->cmd.num_args = 0;
      for (int i = 2; i < cmd->num_args && b->cmd.num_args < MAX_ARGS; i++) {
        strncpy(b->cmd.args[b->cmd.num_args], cmd->args[i], MAX_ARG_LEN - 1);
        b->cmd.num_args++;
      }
      cfg->num_bindings++;
    }
  } else if (str_eq_nocase(cmd->name, "sessionname") &&
             cmd->num_args >= 1) {
    strncpy(cfg->session_name, cmd->args[0], MAX_CMD_LEN - 1);
  } else if (str_eq_nocase(cmd->name, "shelltitle") &&
             cmd->num_args >= 1) {
    strncpy(cfg->shell_title, cmd->args[0], MAX_CMD_LEN - 1);
  } else if (str_eq_nocase(cmd->name, "caption") && cmd->num_args >= 1) {
    strncpy(cfg->caption, cmd->args[0], MAX_CMD_LEN - 1);
  } else if (str_eq_nocase(cmd->name, "hardstatus") &&
             cmd->num_args >= 1) {
    strncpy(cfg->hardstatus, cmd->args[0], MAX_CMD_LEN - 1);
  } else if (str_eq_nocase(cmd->name, "scrollback") &&
             cmd->num_args >= 1) {
    cfg->scroll_back_size = atoi(cmd->args[0]);
    if (cfg->scroll_back_size < 0)
      cfg->scroll_back_size = 0;
    if (cfg->scroll_back_size > 100000)
      cfg->scroll_back_size = 100000;
  } else if (str_eq_nocase(cmd->name, "vbell")) {
    if (cmd->num_args >= 1 && str_eq_nocase(cmd->args[0], "on"))
      cfg->visual_bell = 1;
    else
      cfg->visual_bell = 0;
  } else if (str_eq_nocase(cmd->name, "autodetach")) {
    if (cmd->num_args >= 1 && str_eq_nocase(cmd->args[0], "on"))
      cfg->auto_detach = 1;
    else
      cfg->auto_detach = 0;
  } else if (str_eq_nocase(cmd->name, "startup_message")) {
    if (cmd->num_args >= 1 && str_eq_nocase(cmd->args[0], "on"))
      cfg->start_message = 1;
    else
      cfg->start_message = 0;
  } else if (str_eq_nocase(cmd->name, "verbose")) {
    if (cmd->num_args >= 1 && str_eq_nocase(cmd->args[0], "on"))
      cfg->verbose = 1;
    else
      cfg->verbose = 0;
  }
  /* Other commands are parsed but don't modify state */
}

/* Parse a screenrc-style configuration buffer */
static void parse_screenrc(const char *data, size_t len, ScreenConfig *cfg) {
  const char *p = data;
  const char *end = data + len;

  while (p < end) {
    /* Skip to start of line */
    p = skip_ws(p, end);

    /* Skip comments and blank lines */
    if (p >= end)
      break;
    if (*p == '#' || *p == '\n') {
      while (p < end && *p != '\n')
        p++;
      if (p < end)
        p++;
      continue;
    }

    /* Parse command */
    ScreenCommand cmd;
    memset(&cmd, 0, sizeof(cmd));

    p = parse_token(p, end, cmd.name, MAX_CMD_LEN);

    /* Parse arguments */
    while (p < end && *p != '\n' && cmd.num_args < MAX_ARGS) {
      p = skip_ws(p, end);
      if (p >= end || *p == '\n' || *p == '#')
        break;
      p = parse_token(p, end, cmd.args[cmd.num_args], MAX_ARG_LEN);
      if (cmd.args[cmd.num_args][0] != '\0')
        cmd.num_args++;
    }

    /* Skip to end of line */
    while (p < end && *p != '\n')
      p++;
    if (p < end)
      p++;

    process_command(cfg, &cmd);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 32768)
    return 0;

  char *str = (char *)malloc(size + 1);
  if (!str)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  ScreenConfig cfg;
  config_init(&cfg);
  parse_screenrc(str, size, &cfg);

  free(str);
  return 0;
}

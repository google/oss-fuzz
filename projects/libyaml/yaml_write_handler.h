// Copyright 2020 Google LLC
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

#ifndef YAML_WRITE_HANDLER_H_
#define YAML_WRITE_HANDLER_H_

typedef struct yaml_output_buffer {
  unsigned char *buf;
  size_t size;
  size_t capacity;
} yaml_output_buffer_t;

static int yaml_write_handler(void *data, unsigned char *buffer, size_t size) {
  size_t newsize;
  yaml_output_buffer_t *out = (yaml_output_buffer_t *)data;

  /* Double buffer size whenever necessary */
  if (out->size + size >= out->capacity) {
    newsize = out->capacity << 1;
    if (newsize < out->size + size) {
      newsize = out->size + size;
    }
    out->buf = (unsigned char *)realloc(out->buf, newsize);
    out->capacity = newsize;
  }
  if (!out->buf) {
    out->size = 0;
    return 0;
  }

  memcpy(out->buf + out->size, buffer, size);
  out->size += size;
  return 1;
}

#endif // YAML_WRITE_HANDLER_H_

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

#include "ngx_core.h"

ngx_pool_t *ngx_create_pool(size_t size) {
  (void)size;
  return (ngx_pool_t *)calloc(1, sizeof(ngx_pool_t));
}

void ngx_destroy_pool(ngx_pool_t *pool) {
  ngx_pool_allocation_t *a, *next;

  if (pool == NULL) {
    return;
  }

  for (a = pool->allocs; a != NULL; a = next) {
    next = a->next;
    free(a->ptr);
    free(a);
  }

  free(pool);
}

void *ngx_pnalloc(ngx_pool_t *pool, size_t size) {
  void *ptr;
  ngx_pool_allocation_t *node;

  if (pool == NULL) {
    return NULL;
  }

  if (size == 0) {
    size = 1;
  }

  ptr = malloc(size);
  if (ptr == NULL) {
    return NULL;
  }

  node = (ngx_pool_allocation_t *)malloc(sizeof(ngx_pool_allocation_t));
  if (node == NULL) {
    free(ptr);
    return NULL;
  }

  node->ptr = ptr;
  node->next = pool->allocs;
  pool->allocs = node;

  return ptr;
}

void *ngx_palloc(ngx_pool_t *pool, size_t size) { return ngx_pnalloc(pool, size); }

void *ngx_pcalloc(ngx_pool_t *pool, size_t size) {
  void *p = ngx_pnalloc(pool, size);
  if (p == NULL) {
    return NULL;
  }

  memset(p, 0, (size == 0) ? 1 : size);
  return p;
}

void *ngx_array_push(ngx_array_t *a) {
  void *new_elts;
  size_t old_size, new_nalloc, new_size;

  if (a == NULL || a->pool == NULL || a->size == 0) {
    return NULL;
  }

  if (a->nelts == a->nalloc) {
    new_nalloc = (a->nalloc == 0) ? 4 : a->nalloc * 2;
    if (new_nalloc < a->nalloc || new_nalloc > SIZE_MAX / a->size) {
      return NULL;
    }

    old_size = a->nalloc * a->size;
    new_size = new_nalloc * a->size;

    new_elts = ngx_palloc(a->pool, new_size);
    if (new_elts == NULL) {
      return NULL;
    }

    if (a->elts != NULL && old_size != 0) {
      memcpy(new_elts, a->elts, old_size);
    }

    a->elts = new_elts;
    a->nalloc = (ngx_uint_t)new_nalloc;
  }

  void *elt = (u_char *)a->elts + (a->size * a->nelts);
  a->nelts++;

  return elt;
}

ngx_int_t ngx_hextoi(u_char *line, size_t n) {
  u_char c, ch;
  ngx_int_t value, cutoff;

  if (n == 0) {
    return NGX_ERROR;
  }

  cutoff = NGX_MAX_INT_T_VALUE / 16;

  for (value = 0; n--; line++) {
    if (value > cutoff) {
      return NGX_ERROR;
    }

    ch = *line;

    if (ch >= '0' && ch <= '9') {
      value = value * 16 + (ch - '0');
      continue;
    }

    c = (u_char)(ch | 0x20);

    if (c >= 'a' && c <= 'f') {
      value = value * 16 + (c - 'a' + 10);
      continue;
    }

    return NGX_ERROR;
  }

  return value;
}

ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n) {
  while (n) {
    u_char c1 = (u_char)tolower(*s1++);
    u_char c2 = (u_char)tolower(*s2++);

    if (c1 == c2) {
      n--;
      continue;
    }

    return c1 - c2;
  }

  return 0;
}

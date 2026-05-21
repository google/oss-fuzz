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

#ifndef OSS_FUZZ_NGX_CORE_H
#define OSS_FUZZ_NGX_CORE_H

#include "ngx_config.h"

typedef unsigned char u_char;

typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef intptr_t ngx_flag_t;

#define NGX_OK 0
#define NGX_ERROR -1
#define NGX_DECLINED -5
#define NGX_DONE -4

#define NGX_MAX_INT_T_VALUE ((ngx_int_t)(INTPTR_MAX))

typedef struct {
  size_t len;
  u_char *data;
} ngx_str_t;

typedef struct ngx_pool_allocation_s ngx_pool_allocation_t;

struct ngx_pool_allocation_s {
  void *ptr;
  ngx_pool_allocation_t *next;
};

typedef struct ngx_pool_s ngx_pool_t;

struct ngx_pool_s {
  ngx_pool_allocation_t *allocs;
};

typedef struct {
  void *elts;
  ngx_uint_t nelts;
  size_t size;
  ngx_uint_t nalloc;
  ngx_pool_t *pool;
} ngx_array_t;

#define ngx_inline inline

#define ngx_memcpy memcpy
#define ngx_memcmp memcmp
#define ngx_strlen strlen

#define ngx_str_null(str) \
  do {                    \
    (str)->len = 0;       \
    (str)->data = NULL;   \
  } while (0)

ngx_pool_t *ngx_create_pool(size_t size);
void ngx_destroy_pool(ngx_pool_t *pool);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_array_push(ngx_array_t *a);
ngx_int_t ngx_hextoi(u_char *line, size_t n);
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);

static ngx_inline ngx_int_t ngx_array_init(ngx_array_t *array, ngx_pool_t *pool,
                                           ngx_uint_t n, size_t size) {
  if (n == 0 || size == 0 || n > (SIZE_MAX / size)) {
    return NGX_ERROR;
  }

  array->nelts = 0;
  array->size = size;
  array->nalloc = n;
  array->pool = pool;
  array->elts = ngx_palloc(pool, n * size);

  return (array->elts == NULL) ? NGX_ERROR : NGX_OK;
}

#endif

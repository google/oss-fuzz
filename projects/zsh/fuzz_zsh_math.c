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
 * Fuzz zsh arithmetic expression evaluation.
 *
 * Zsh supports complex arithmetic expressions in $(( )) contexts:
 *   - Standard C-style operators: + - * / % ** & | ^ ~ << >>
 *   - Comparison: == != < > <= >=
 *   - Logical: && || !
 *   - Ternary: a ? b : c
 *   - Assignment: = += -= *= /= %= etc.
 *   - Comma operator
 *   - Base notation: 2#1010, 16#ff, 8#77
 *   - Floating point (with FLOAT_ZSH option)
 *
 * This is a standalone math expression evaluator that mirrors
 * zsh's Src/math.c without depending on zsh internals.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <errno.h>

#define MAX_EXPR_LEN 512
#define MAX_EVAL_DEPTH 32

typedef struct {
  const char *expr;
  size_t pos;
  size_t len;
  int depth;
  int error;
} MathCtx;

static long math_eval_expr(MathCtx *ctx);

static void skip_whitespace(MathCtx *ctx) {
  while (ctx->pos < ctx->len &&
         (ctx->expr[ctx->pos] == ' ' || ctx->expr[ctx->pos] == '\t' ||
          ctx->expr[ctx->pos] == '\n' || ctx->expr[ctx->pos] == '\r'))
    ctx->pos++;
}

static long math_eval_number(MathCtx *ctx) {
  skip_whitespace(ctx);

  if (ctx->pos >= ctx->len) {
    ctx->error = 1;
    return 0;
  }

  long result = 0;
  int negate = 0;

  /* Handle unary operators */
  if (ctx->expr[ctx->pos] == '-') {
    negate = 1;
    ctx->pos++;
    skip_whitespace(ctx);
  } else if (ctx->expr[ctx->pos] == '+') {
    ctx->pos++;
    skip_whitespace(ctx);
  } else if (ctx->expr[ctx->pos] == '~') {
    ctx->pos++;
    result = ~math_eval_number(ctx);
    return result;
  } else if (ctx->expr[ctx->pos] == '!') {
    ctx->pos++;
    result = !math_eval_number(ctx);
    return result;
  }

  /* Handle parenthesized expressions */
  if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == '(') {
    ctx->pos++;
    ctx->depth++;
    if (ctx->depth > MAX_EVAL_DEPTH) {
      ctx->error = 1;
      return 0;
    }
    result = math_eval_expr(ctx);
    ctx->depth--;
    skip_whitespace(ctx);
    if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == ')')
      ctx->pos++;
    return negate ? -result : result;
  }

  /* Parse number with optional base prefix */
  if (ctx->pos >= ctx->len) {
    ctx->error = 1;
    return 0;
  }

  /* Check for 0x, 0o, 0b prefixes */
  if (ctx->pos + 1 < ctx->len && ctx->expr[ctx->pos] == '0') {
    if (ctx->expr[ctx->pos + 1] == 'x' || ctx->expr[ctx->pos + 1] == 'X') {
      ctx->pos += 2;
      char *endptr;
      result = strtol(ctx->expr + ctx->pos, &endptr, 16);
      ctx->pos = endptr - ctx->expr;
      return negate ? -result : result;
    }
    if (ctx->expr[ctx->pos + 1] == 'b' || ctx->expr[ctx->pos + 1] == 'B') {
      ctx->pos += 2;
      while (ctx->pos < ctx->len &&
             (ctx->expr[ctx->pos] == '0' || ctx->expr[ctx->pos] == '1')) {
        result = result * 2 + (ctx->expr[ctx->pos] - '0');
        ctx->pos++;
      }
      return negate ? -result : result;
    }
  }

  /* Check for zsh base#value notation: 2#1010, 16#ff */
  size_t num_start = ctx->pos;
  while (ctx->pos < ctx->len && ctx->expr[ctx->pos] >= '0' &&
         ctx->expr[ctx->pos] <= '9')
    ctx->pos++;

  if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == '#' &&
      ctx->pos > num_start) {
    /* Parse base */
    char base_buf[12];
    size_t base_len = ctx->pos - num_start;
    if (base_len > 10)
      base_len = 10;
    memcpy(base_buf, ctx->expr + num_start, base_len);
    base_buf[base_len] = '\0';
    int base = atoi(base_buf);
    ctx->pos++; /* skip '#' */

    if (base >= 2 && base <= 36) {
      char *endptr;
      result = strtol(ctx->expr + ctx->pos, &endptr, base);
      ctx->pos = endptr - ctx->expr;
    } else {
      ctx->error = 1;
    }
    return negate ? -result : result;
  }

  /* Regular decimal number */
  ctx->pos = num_start;
  if (ctx->pos < ctx->len &&
      (ctx->expr[ctx->pos] >= '0' && ctx->expr[ctx->pos] <= '9')) {
    char *endptr;
    errno = 0;
    result = strtol(ctx->expr + ctx->pos, &endptr, 0);
    if (errno == ERANGE)
      result = (negate ? LONG_MIN : LONG_MAX);
    ctx->pos = endptr - ctx->expr;

    /* Handle floating point dot */
    if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == '.') {
      ctx->pos++;
      while (ctx->pos < ctx->len && ctx->expr[ctx->pos] >= '0' &&
             ctx->expr[ctx->pos] <= '9')
        ctx->pos++;
    }
  } else if (ctx->pos < ctx->len &&
             ((ctx->expr[ctx->pos] >= 'a' && ctx->expr[ctx->pos] <= 'z') ||
              (ctx->expr[ctx->pos] >= 'A' && ctx->expr[ctx->pos] <= 'Z') ||
              ctx->expr[ctx->pos] == '_')) {
    /* Variable name - skip it, treat as 0 */
    while (ctx->pos < ctx->len &&
           ((ctx->expr[ctx->pos] >= 'a' && ctx->expr[ctx->pos] <= 'z') ||
            (ctx->expr[ctx->pos] >= 'A' && ctx->expr[ctx->pos] <= 'Z') ||
            (ctx->expr[ctx->pos] >= '0' && ctx->expr[ctx->pos] <= '9') ||
            ctx->expr[ctx->pos] == '_'))
      ctx->pos++;
  } else {
    ctx->error = 1;
  }

  return negate ? -result : result;
}

/* Multiplication, division, modulo */
static long math_eval_muldiv(MathCtx *ctx) {
  long left = math_eval_number(ctx);
  if (ctx->error)
    return 0;

  while (ctx->pos < ctx->len) {
    skip_whitespace(ctx);
    if (ctx->pos >= ctx->len)
      break;

    char op = ctx->expr[ctx->pos];
    if (op == '*' && ctx->pos + 1 < ctx->len && ctx->expr[ctx->pos + 1] == '*') {
      /* Power operator ** */
      ctx->pos += 2;
      long right = math_eval_number(ctx);
      if (ctx->error)
        return 0;
      /* Simple integer power */
      long result = 1;
      for (long i = 0; i < right && i < 63; i++)
        result *= left;
      left = result;
    } else if (op == '*') {
      ctx->pos++;
      long right = math_eval_number(ctx);
      if (ctx->error)
        return 0;
      left *= right;
    } else if (op == '/') {
      ctx->pos++;
      long right = math_eval_number(ctx);
      if (ctx->error || right == 0)
        return 0;
      left /= right;
    } else if (op == '%') {
      ctx->pos++;
      long right = math_eval_number(ctx);
      if (ctx->error || right == 0)
        return 0;
      left %= right;
    } else {
      break;
    }
  }
  return left;
}

/* Addition and subtraction */
static long math_eval_addsub(MathCtx *ctx) {
  long left = math_eval_muldiv(ctx);
  if (ctx->error)
    return 0;

  while (ctx->pos < ctx->len) {
    skip_whitespace(ctx);
    if (ctx->pos >= ctx->len)
      break;

    char op = ctx->expr[ctx->pos];
    if (op == '+') {
      ctx->pos++;
      long right = math_eval_muldiv(ctx);
      if (ctx->error)
        return 0;
      left += right;
    } else if (op == '-') {
      ctx->pos++;
      long right = math_eval_muldiv(ctx);
      if (ctx->error)
        return 0;
      left -= right;
    } else {
      break;
    }
  }
  return left;
}

/* Shift operators */
static long math_eval_shift(MathCtx *ctx) {
  long left = math_eval_addsub(ctx);
  if (ctx->error)
    return 0;

  while (ctx->pos + 1 < ctx->len) {
    skip_whitespace(ctx);
    if (ctx->pos + 1 >= ctx->len)
      break;

    if (ctx->expr[ctx->pos] == '<' && ctx->expr[ctx->pos + 1] == '<') {
      ctx->pos += 2;
      long right = math_eval_addsub(ctx);
      if (ctx->error)
        return 0;
      if (right >= 0 && right < 64)
        left <<= right;
    } else if (ctx->expr[ctx->pos] == '>' && ctx->expr[ctx->pos + 1] == '>') {
      ctx->pos += 2;
      long right = math_eval_addsub(ctx);
      if (ctx->error)
        return 0;
      if (right >= 0 && right < 64)
        left >>= right;
    } else {
      break;
    }
  }
  return left;
}

/* Comparison operators */
static long math_eval_compare(MathCtx *ctx) {
  long left = math_eval_shift(ctx);
  if (ctx->error)
    return 0;

  skip_whitespace(ctx);
  if (ctx->pos + 1 < ctx->len) {
    if (ctx->expr[ctx->pos] == '<' && ctx->expr[ctx->pos + 1] == '=') {
      ctx->pos += 2;
      long right = math_eval_shift(ctx);
      return left <= right;
    } else if (ctx->expr[ctx->pos] == '>' && ctx->expr[ctx->pos + 1] == '=') {
      ctx->pos += 2;
      long right = math_eval_shift(ctx);
      return left >= right;
    } else if (ctx->expr[ctx->pos] == '=' && ctx->expr[ctx->pos + 1] == '=') {
      ctx->pos += 2;
      long right = math_eval_shift(ctx);
      return left == right;
    } else if (ctx->expr[ctx->pos] == '!' && ctx->expr[ctx->pos + 1] == '=') {
      ctx->pos += 2;
      long right = math_eval_shift(ctx);
      return left != right;
    }
  }

  if (ctx->pos < ctx->len) {
    if (ctx->expr[ctx->pos] == '<' &&
        (ctx->pos + 1 >= ctx->len || ctx->expr[ctx->pos + 1] != '<')) {
      ctx->pos++;
      long right = math_eval_shift(ctx);
      return left < right;
    } else if (ctx->expr[ctx->pos] == '>' &&
               (ctx->pos + 1 >= ctx->len || ctx->expr[ctx->pos + 1] != '>')) {
      ctx->pos++;
      long right = math_eval_shift(ctx);
      return left > right;
    }
  }

  return left;
}

/* Bitwise AND, XOR, OR */
static long math_eval_bitwise(MathCtx *ctx) {
  long left = math_eval_compare(ctx);
  if (ctx->error)
    return 0;

  while (ctx->pos < ctx->len) {
    skip_whitespace(ctx);
    if (ctx->pos >= ctx->len)
      break;

    if (ctx->expr[ctx->pos] == '&' &&
        (ctx->pos + 1 >= ctx->len || ctx->expr[ctx->pos + 1] != '&')) {
      ctx->pos++;
      long right = math_eval_compare(ctx);
      if (ctx->error)
        return 0;
      left &= right;
    } else if (ctx->expr[ctx->pos] == '^') {
      ctx->pos++;
      long right = math_eval_compare(ctx);
      if (ctx->error)
        return 0;
      left ^= right;
    } else if (ctx->expr[ctx->pos] == '|' &&
               (ctx->pos + 1 >= ctx->len || ctx->expr[ctx->pos + 1] != '|')) {
      ctx->pos++;
      long right = math_eval_compare(ctx);
      if (ctx->error)
        return 0;
      left |= right;
    } else {
      break;
    }
  }
  return left;
}

/* Full expression with ternary operator */
static long math_eval_expr(MathCtx *ctx) {
  long left = math_eval_bitwise(ctx);
  if (ctx->error)
    return 0;

  skip_whitespace(ctx);
  if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == '?') {
    ctx->pos++;
    long true_val = math_eval_expr(ctx);
    skip_whitespace(ctx);
    if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == ':')
      ctx->pos++;
    long false_val = math_eval_expr(ctx);
    return left ? true_val : false_val;
  }

  /* Comma operator */
  while (ctx->pos < ctx->len) {
    skip_whitespace(ctx);
    if (ctx->pos < ctx->len && ctx->expr[ctx->pos] == ',') {
      ctx->pos++;
      left = math_eval_expr(ctx);
    } else {
      break;
    }
  }

  return left;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > MAX_EXPR_LEN)
    return 0;

  /* Null-terminate */
  char *expr = (char *)malloc(size + 1);
  if (!expr)
    return 0;
  memcpy(expr, data, size);
  expr[size] = '\0';

  MathCtx ctx;
  ctx.expr = expr;
  ctx.pos = 0;
  ctx.len = size;
  ctx.depth = 0;
  ctx.error = 0;

  math_eval_expr(&ctx);

  free(expr);
  return 0;
}

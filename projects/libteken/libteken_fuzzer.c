#include <stdint.h>
#include <stdio.h>

#include <teken.h>

static void dummy_bell(void *s) {}
static void dummy_cursor(void *s, const teken_pos_t *p) {}
static void dummy_putchar(void *s, const teken_pos_t *p, teken_char_t c,
                          const teken_attr_t *a) {}
static void dummy_fill(void *s, const teken_rect_t *r, teken_char_t c,
                       const teken_attr_t *a) {}
static void dummy_copy(void *s, const teken_rect_t *r, const teken_pos_t *p) {}
static void dummy_param(void *s, int cmd, unsigned int value) {}
static void dummy_respond(void *s, const void *buf, size_t len) {}

static teken_funcs_t tf = {
    .tf_bell = dummy_bell,
    .tf_cursor = dummy_cursor,
    .tf_putchar = dummy_putchar,
    .tf_fill = dummy_fill,
    .tf_copy = dummy_copy,
    .tf_param = dummy_param,
    .tf_respond = dummy_respond,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  teken_t t = { 0 };
  teken_init(&t, &tf, NULL);
  teken_input(&t, data, size);
  return 0;
}

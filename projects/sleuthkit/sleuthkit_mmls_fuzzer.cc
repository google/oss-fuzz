#include <stddef.h>
#include <stdint.h>

#include "sleuthkit_mem_img.h"
#include "sleuthkit/tsk/tsk_tools_i.h"

#ifndef VSTYPE
#error Define VSTYPE as a valid value of TSK_VS_TYPE_ENUM.
#endif

static TSK_WALK_RET_ENUM
part_act(TSK_VS_INFO * vs, const TSK_VS_PART_INFO * part, void *ptr) {
  return TSK_WALK_CONT;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TSK_IMG_INFO* img;
  TSK_VS_INFO* vs;

  img = mem_open(data, size);
  if (img == nullptr) return 0;

  vs = tsk_vs_open(img, 0, VSTYPE);
  if (vs == nullptr) goto out;

  tsk_vs_part_walk(vs, 0, vs->part_count - 1,
      TSK_VS_PART_FLAG_ALL, part_act, nullptr);

  tsk_vs_close(vs);

out:
  img->close(img);

  return 0;
}

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "ext2fs/ext2fs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char* pattern = "/dev/shm/ext2XXXXXX";
  int fd;
  char* fname;

  // Write our data to a temp file.
  fname = strdup(pattern);
  fd = mkstemp(fname);
  write(fd, data, size);
  close(fd);

  ext2_filsys fs;
  errcode_t retval = ext2fs_open(
      fname,
      0, 0, 0,
      unix_io_manager,
      &fs);
  if (retval != 0) {
    goto out;
  }

  retval = ext2fs_read_inode_bitmap(fs);
  if (retval != 0) {
    goto out2;
  }
  retval = ext2fs_read_block_bitmap(fs);
  if (retval != 0) {
    goto out2;
  }
  retval = ext2fs_check_directory(fs, EXT2_ROOT_INO);
  if (retval != 0) {
    goto out2;
  }

out2:
  ext2fs_close(fs);

out:
  unlink(fname);
  free(fname);
  return 0;  // other return values are reserved for future use
}

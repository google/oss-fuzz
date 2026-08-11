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

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <string>

#include "ext2fs/ext2fs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1024) return 0;

  int fd = syscall(SYS_memfd_create, "ext2_write_fuzzer", 0);
  if (fd < 0) return 0;
  if (write(fd, data, size) != (ssize_t)size) {
    close(fd);
    return 0;
  }

  std::string fspath = "/proc/self/fd/" + std::to_string(fd);
  ext2_filsys fs;
  if (ext2fs_open(fspath.c_str(),
                  EXT2_FLAG_RW | EXT2_FLAG_IGNORE_CSUM_ERRORS, 0, 0,
                  unix_io_manager, &fs)) {
    close(fd);
    return 0;
  }

  if (ext2fs_read_bitmaps(fs)) {
    ext2fs_close(fs);
    close(fd);
    return 0;
  }

  // ---- Block allocation / freeing ----
  blk64_t alloc_blk = 0;
  if (!ext2fs_new_block2(fs, 0, nullptr, &alloc_blk)) {
    ext2fs_block_alloc_stats2(fs, alloc_blk, +1);
    ext2fs_block_alloc_stats2(fs, alloc_blk, -1);
  }

  // ---- Inode allocation + write_inode ----
  ext2_ino_t new_ino = 0;
  if (!ext2fs_new_inode(fs, EXT2_ROOT_INO, LINUX_S_IFREG | 0644, nullptr,
                        &new_ino) && new_ino) {
    ext2fs_inode_alloc_stats2(fs, new_ino, +1, 0);
    struct ext2_inode inode = {};
    inode.i_mode = LINUX_S_IFREG | 0644;
    inode.i_links_count = 1;
    ext2fs_write_new_inode(fs, new_ino, &inode);
    ext2fs_write_inode(fs, new_ino, &inode);

    // Try to attach the new inode under root with a fresh name.
    if (!ext2fs_link(fs, EXT2_ROOT_INO, "fuzzlnk", new_ino,
                     EXT2_FT_REG_FILE)) {
      ext2fs_unlink(fs, EXT2_ROOT_INO, "fuzzlnk", new_ino, 0);
    }

    struct ext2_xattr_handle *xh = nullptr;
    if (!ext2fs_xattrs_open(fs, new_ino, &xh) && xh) {
      const char *val = "v";
      if (!ext2fs_xattr_set(xh, "user.fuzz", val, 1)) {
        ext2fs_xattrs_write(xh);
        ext2fs_xattr_remove(xh, "user.fuzz");
        ext2fs_xattrs_write(xh);
      }
      ext2fs_xattrs_close(&xh);
    }

    ext2fs_inode_alloc_stats2(fs, new_ino, -1, 0);
  }

  // ---- mkdir + bulk-link many entries to push htree split paths ----
  if (!ext2fs_new_inode(fs, EXT2_ROOT_INO, LINUX_S_IFDIR | 0755, nullptr,
                        &new_ino) && new_ino) {
    if (!ext2fs_mkdir(fs, EXT2_ROOT_INO, new_ino, "fdir")) {
      for (int i = 0; i < 32; ++i) {
        char name[32];
        snprintf(name, sizeof(name), "ent_%08x", i);
        ext2fs_link(fs, new_ino, name, EXT2_ROOT_INO, EXT2_FT_REG_FILE);
      }
      ext2fs_expand_dir(fs, new_ino);
    }
  }

  // ---- bmap2 with BMAP_ALLOC on the root inode forces block allocation
  // through alloc.c / bmap.c / extent.c. ----
  {
    struct ext2_inode root_ino_for_bmap;
    if (!ext2fs_read_inode(fs, EXT2_ROOT_INO, &root_ino_for_bmap)) {
      blk64_t phys;
      ext2fs_bmap2(fs, EXT2_ROOT_INO, &root_ino_for_bmap, nullptr,
                   BMAP_ALLOC, 0, nullptr, &phys);
    }
  }

  // ---- dblist: collect directory blocks and replay them ----
  ext2_dblist dblist = nullptr;
  if (!ext2fs_init_dblist(fs, &dblist)) {
    ext2fs_add_dir_block2(dblist, EXT2_ROOT_INO, 0, 0);
    ext2fs_dblist_sort(dblist, nullptr);
    ext2fs_dblist_iterate(dblist, [](ext2_filsys, struct ext2_db_entry *,
                                     void *) { return 0; }, nullptr);
    ext2fs_free_dblist(dblist);
  }

  // ---- punch (free a range of blocks) on the root inode ----
  struct ext2_inode root_inode;
  if (!ext2fs_read_inode(fs, EXT2_ROOT_INO, &root_inode)) {
    ext2fs_punch(fs, EXT2_ROOT_INO, &root_inode, nullptr, 0, 1);
  }

  // ---- Walk every inode; for files with extents, exercise extent_set_bmap
  // and extent_replace; for inodes with xattrs, set + remove a key. Caps the
  // scan at 64 inodes to keep wall-time per exec manageable. ----
  ext2_inode_scan scan;
  if (!ext2fs_open_inode_scan(fs, 0, &scan)) {
    ext2_ino_t ino;
    struct ext2_inode inode;
    int budget = 64;
    while (budget-- > 0 &&
           !ext2fs_get_next_inode(scan, &ino, &inode) &&
           ino != 0) {
      if ((inode.i_flags & EXT4_EXTENTS_FL) && LINUX_S_ISREG(inode.i_mode)) {
        ext2_extent_handle_t h;
        if (!ext2fs_extent_open(fs, ino, &h)) {
          ext2fs_extent_set_bmap(h, 0, 0, 0);
          // Walk to a leaf and try a few mutating operations.
          struct ext2fs_extent extent;
          if (!ext2fs_extent_get(h, EXT2_EXTENT_ROOT, &extent)) {
            ext2fs_extent_fix_parents(h);
            ext2fs_extent_node_split(h);
            // Delete and re-walk — exercises rebalance paths.
            ext2fs_extent_delete(h, 0);
          }
          ext2fs_extent_free(h);
        }
        // ext2fs_punch on the same inode hits the extent-aware free path.
        ext2fs_punch(fs, ino, &inode, nullptr, 0, ~0ULL);
      }
      struct ext2_xattr_handle *xh = nullptr;
      if (!ext2fs_xattrs_open(fs, ino, &xh) && xh) {
        const char *val = "x";
        if (!ext2fs_xattr_set(xh, "user.fz", val, 1))
          ext2fs_xattr_remove(xh, "user.fz");
        ext2fs_xattrs_close(&xh);
      }
    }
    ext2fs_close_inode_scan(scan);
  }

  // ---- icount: build an in-memory inode-link-count table and exercise it
  // against the on-disk inode scan ----
  ext2_icount_t icount = nullptr;
  if (!ext2fs_create_icount2(fs, 0, 0, nullptr, &icount) && icount) {
    ext2_inode_scan ic_scan;
    if (!ext2fs_open_inode_scan(fs, 0, &ic_scan)) {
      ext2_ino_t ino;
      struct ext2_inode inode;
      int budget = 64;
      while (budget-- > 0 &&
             !ext2fs_get_next_inode(ic_scan, &ino, &inode) &&
             ino != 0) {
        __u16 ret;
        ext2fs_icount_store(icount, ino, inode.i_links_count);
        ext2fs_icount_increment(icount, ino, &ret);
        ext2fs_icount_decrement(icount, ino, &ret);
        ext2fs_icount_fetch(icount, ino, &ret);
      }
      ext2fs_close_inode_scan(ic_scan);
    }
    ext2fs_icount_validate(icount, stderr);
    ext2fs_free_icount(icount);
  }

  // ---- Inline data create/set on a fresh inode ----
  if (!ext2fs_new_inode(fs, EXT2_ROOT_INO, LINUX_S_IFREG | 0644, nullptr,
                        &new_ino) && new_ino) {
    struct ext2_inode inline_inode = {};
    inline_inode.i_mode = LINUX_S_IFREG | 0644;
    inline_inode.i_links_count = 1;
    if (!ext2fs_write_new_inode(fs, new_ino, &inline_inode) &&
        !ext2fs_inline_data_init(fs, new_ino)) {
      char small_buf[40] = {};
      ext2fs_inline_data_set(fs, new_ino, &inline_inode,
                             small_buf, sizeof(small_buf));
      size_t got = 0;
      ext2fs_inline_data_size(fs, new_ino, &got);
    }
  }

  // ---- Journal inode creation — drags in mkjournal.c writeback paths. ----
  ext2fs_add_journal_inode2(fs, 8, 0, 0);

  // ---- Misc write-side paths that don't need a specific inode. ----
  ext2fs_create_orphan_file(fs, 4);
  ext2fs_set_gdt_csum(fs);

  // ---- Flush dirty bitmaps + superblock — drives close/csum write paths ----
  ext2fs_flush(fs);

  ext2fs_close(fs);
  close(fd);
  return 0;
}

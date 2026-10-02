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

namespace {

int dir_cb(struct ext2_dir_entry *de, int /*offset*/, int /*blocksize*/,
           char * /*buf*/, void *priv) {
  ext2_filsys fs = static_cast<ext2_filsys>(priv);
  if (!fs) return 0;
  // Touch ext2fs_check_directory, ext2fs_read_inode, and ext2fs_get_pathname
  // against every directory entry we encounter — exercises namei, inode
  // reads, and pathname assembly with a stream of attacker-controlled inode
  // numbers.
  ext2fs_check_directory(fs, de->inode);
  struct ext2_inode inode;
  if (!ext2fs_read_inode(fs, de->inode, &inode)) {
    char *path = nullptr;
    if (!ext2fs_get_pathname(fs, EXT2_ROOT_INO, de->inode, &path)) {
      ext2fs_free_mem(&path);
    }
  }
  // dirhash + lookup against the name we just saw — exercises dirhash.c and
  // lookup.c (htree walking) for every directory entry in the corpus.
  int namelen = ext2fs_dirent_name_len(de);
  if (namelen > 0 && namelen < 256) {
    ext2_dirhash_t hash, minor_hash;
    ext2fs_dirhash(EXT2_HASH_HALF_MD4, de->name, namelen, nullptr,
                   &hash, &minor_hash);
    ext2_ino_t out_ino;
    ext2fs_lookup(fs, EXT2_ROOT_INO, de->name, namelen, nullptr, &out_ino);
  }
  return 0;
}

int block_cb(ext2_filsys, blk64_t *, e2_blkcnt_t, blk64_t, int, void *) {
  return 0;
}

int xattr_cb(char * /*name*/, char * /*value*/, size_t /*value_len*/,
             void * /*priv*/) {
  return 0;
}

void walk_extents(ext2_filsys fs, ext2_ino_t ino) {
  ext2_extent_handle_t h;
  if (ext2fs_extent_open(fs, ino, &h))
    return;
  // ext2fs_extent_get_info exercises a path independent of node traversal.
  struct ext2_extent_info info;
  ext2fs_extent_get_info(h, &info);

  struct ext2fs_extent extent;
  int budget = 256;
  for (int op : {EXT2_EXTENT_ROOT, EXT2_EXTENT_FIRST_SIB,
                 EXT2_EXTENT_LAST_SIB, EXT2_EXTENT_NEXT_LEAF,
                 EXT2_EXTENT_PREV_LEAF, EXT2_EXTENT_LAST_LEAF}) {
    if (budget-- <= 0) break;
    ext2fs_extent_get(h, op, &extent);
  }
  errcode_t e = ext2fs_extent_get(h, EXT2_EXTENT_ROOT, &extent);
  while (!e && budget-- > 0)
    e = ext2fs_extent_get(h, EXT2_EXTENT_NEXT, &extent);
  ext2fs_extent_free(h);
}

void walk_xattrs(ext2_filsys fs, ext2_ino_t ino) {
  struct ext2_xattr_handle *xh = nullptr;
  if (ext2fs_xattrs_open(fs, ino, &xh) || !xh)
    return;
  if (!ext2fs_xattrs_read(xh)) {
    size_t count = 0;
    ext2fs_xattrs_count(xh, &count);
    ext2fs_xattrs_iterate(xh, xattr_cb, nullptr);
  }
  ext2fs_xattrs_close(&xh);
}

void walk_bmap(ext2_filsys fs, ext2_ino_t ino, const struct ext2_inode &inode) {
  // ext2fs_bmap2 exercises the indirect/extent block mapping resolver. Cap at
  // a handful of logical blocks so we don't dominate fuzzing time on huge
  // files.
  blk64_t phys;
  int budget = 16;
  for (blk64_t lblk = 0; budget-- > 0; ++lblk) {
    if (ext2fs_bmap2(fs, ino, (struct ext2_inode *)&inode, nullptr, 0, lblk,
                     nullptr, &phys))
      break;
    if (!phys)
      break;
  }
}

void read_file(ext2_filsys fs, ext2_ino_t ino) {
  ext2_file_t file;
  if (ext2fs_file_open(fs, ino, 0, &file))
    return;
  char buf[4096];
  unsigned int got;
  int budget = 32;  // cap reads per file
  while (budget-- > 0 && !ext2fs_file_read(file, buf, sizeof(buf), &got) && got)
    ;
  ext2fs_file_close(file);
}

void try_xattr_get(ext2_filsys fs, ext2_ino_t ino) {
  struct ext2_xattr_handle *xh = nullptr;
  if (ext2fs_xattrs_open(fs, ino, &xh) || !xh)
    return;
  if (!ext2fs_xattrs_read(xh)) {
    static const char *keys[] = {
        "user.test", "system.posix_acl_access",
        "security.selinux", "trusted.foo",
    };
    for (const char *k : keys) {
      void *value = nullptr;
      size_t value_len = 0;
      if (!ext2fs_xattr_get(xh, k, &value, &value_len) && value)
        ext2fs_free_mem(&value);
    }
  }
  ext2fs_xattrs_close(&xh);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1024) return 0;

  int fd = syscall(SYS_memfd_create, "ext2_iter_fuzzer", 0);
  if (fd < 0) return 0;
  if (write(fd, data, size) != (ssize_t)size) {
    close(fd);
    return 0;
  }

  std::string fspath = "/proc/self/fd/" + std::to_string(fd);
  ext2_filsys fs;
  if (ext2fs_open(fspath.c_str(), EXT2_FLAG_IGNORE_CSUM_ERRORS, 0, 0,
                  unix_io_manager, &fs)) {
    close(fd);
    return 0;
  }

  ext2fs_read_bitmaps(fs);
  // Block-group descriptor verification — a chunky csum.c / blknum.c path.
  ext2fs_check_desc(fs);

  // Walk the directory tree from the root once. dir_cb itself dives back into
  // per-inode APIs (check_directory, read_inode, get_pathname) so this alone
  // covers a lot of ground beyond inode scan + leaf-block iteration.
  ext2fs_dir_iterate(fs, EXT2_ROOT_INO, 0, nullptr, dir_cb, fs);

  ext2_inode_scan scan;
  if (!ext2fs_open_inode_scan(fs, 0, &scan)) {
    ext2_ino_t ino;
    struct ext2_inode inode;
    int budget = 512;
    while (budget-- > 0 &&
           !ext2fs_get_next_inode(scan, &ino, &inode) &&
           ino != 0) {
      walk_xattrs(fs, ino);
      try_xattr_get(fs, ino);
      if (LINUX_S_ISDIR(inode.i_mode)) {
        ext2fs_dir_iterate(fs, ino, 0, nullptr, dir_cb, fs);
      } else if (LINUX_S_ISREG(inode.i_mode) || LINUX_S_ISLNK(inode.i_mode)) {
        if (inode.i_flags & EXT4_EXTENTS_FL) {
          walk_extents(fs, ino);
        } else {
          ext2fs_block_iterate3(fs, ino, 0, nullptr, block_cb, nullptr);
        }
        walk_bmap(fs, ino, inode);
        read_file(fs, ino);
      }
    }
    ext2fs_close_inode_scan(scan);
  }

  ext2fs_close(fs);
  close(fd);
  return 0;
}

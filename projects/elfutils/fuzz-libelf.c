/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


void fuzz_logic_one(char *filename, int compression_type) {
  (void)elf_version(EV_CURRENT);
  int fd = open(filename, O_RDONLY);
  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if (elf != NULL) {
    size_t strndx;
    elf_getshdrstrndx(elf, &strndx);

    Elf_Scn *scn = NULL;
    // Iterate through sections
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
      GElf_Shdr mem;
      GElf_Shdr *shdr = gelf_getshdr(scn, &mem);
      const char *name = elf_strptr(elf, strndx, shdr->sh_name);

      // Two options for reading sections. We keep the code structure
      // so it resembles the test code.
      // Compress and get data of the section
      if ((shdr->sh_flags & SHF_COMPRESSED) != 0) {
        if (elf_compress(scn, compression_type, 0) >= 0) {
          elf_getdata(scn, NULL);
        }
      } else if (name != NULL) {
        if (name[0] == '.' && name[1] == 'z') {
          if (elf_compress_gnu(scn, 0, 0) >= 0) {
            elf_getdata(scn, NULL);
          }
        }
      }
    }
    elf_end(elf);
  }
  close(fd);
}

void fuzz_logic_twice(char *filename, int open_flags, Elf_Cmd cmd) {
  (void)elf_version(EV_CURRENT);
  int fd = open(filename, open_flags);
  Elf *elf = elf_begin(fd, cmd, NULL);
  if (elf != NULL) {
    size_t elf_size = 0;
    elf_rawfile(elf, &elf_size);
    elf_end(elf);
  }
  close(fd);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  fuzz_logic_one(filename, 0);
  fuzz_logic_one(filename, 1);
  fuzz_logic_twice(filename, O_RDONLY, ELF_C_READ);
  fuzz_logic_twice(filename, O_RDONLY | O_WRONLY, ELF_C_RDWR);
  fuzz_logic_twice(filename, O_RDONLY, ELF_C_READ_MMAP);
  fuzz_logic_twice(filename, O_RDONLY | O_WRONLY, ELF_C_RDWR_MMAP);

  unlink(filename);
  return 0;
}

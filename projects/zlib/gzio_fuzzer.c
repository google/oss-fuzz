/********************************************************************************
 * Copyright 2025 Google LLC
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
 *
 *******************************************************************************/
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

#undef gzgetc

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {

    gzFile file;
    char fname[] = "gzio.XXXXXX";
    close(mkstemp(fname));
    unsigned mode_sz = (dataLen ? (--dataLen, *data++) | 2 : 8) & 0xF;
    char mode[mode_sz];
    memcpy(mode, data, dataLen >= mode_sz ? mode_sz - 1: dataLen);
    mode[mode_sz - 1] = 0;
    file = gzopen(fname, mode);

    /* Chain I/O operations on a file opened with random mode the nature of the
     * operation and their operand are controlled by the fuzzer
     */
    int op_count = 2; //< Number of operations chained.
    while(op_count--) {
      switch((--dataLen, (*data)%19)) {
        case 0: {
          char c = dataLen ? (--dataLen, (char)*data++) : 'c';
          if(gzputc(file, c) < 0) {
            goto exit;
          }
          break;
        }
        case 1: {
          unsigned sz = dataLen ? ((--dataLen, *data++)&0xF) + 1 : 8;
          char input[sz];
          memcpy(input, data, dataLen >= sz ? sz - 1: dataLen);
          input[sz - 1] = 0;
          if(gzputs(file, input) < 0)
            goto exit;
          break;
        }
        case 2: {
          unsigned sz = dataLen ? ((--dataLen, *data++)&0xF) + 1 : 8;
          unsigned nitems = dataLen ? ((--dataLen, *data++)&0xF) + 1 : 8;
          unsigned count = sz * nitems;
          char input[count];
          memcpy(input, data, dataLen >= count ? count - 1: dataLen);
          input[count - 1] = 0;
          if(gzfwrite(input, sz, nitems, file) <= 0)
            goto exit;
          break;
        }
        case 3: {
          unsigned sz = dataLen ? (--dataLen, *data++) : 8;
          char uncompr[sz];
          if(gzread(file, uncompr, sz) < 0)
            goto exit;
          break;
        }
        case 4: {
          int whences[5] = {SEEK_CUR, SEEK_SET, SEEK_END, 18};
          int whence = dataLen ? (--dataLen, whences[(*data++)%6]) : SEEK_CUR;
          long offset = dataLen >= sizeof(long) ? (*(long*)data &0xFF) + 1: 1L;
          if(gzseek(file, offset, whence) < 0)
            goto exit;
          break;
        }
        case 5:
          gztell(file);
          break;
        case 6:
          gzgetc(file);
          break;
        case 7: {
          char c = dataLen ? (--dataLen, (char)*data++) : 'c';
          if(gzungetc(c, file) < 0)
            goto exit;
          break;
        }
        case 8: {
          unsigned sz = dataLen ? (--dataLen, *data++) : 8;
          char uncompr[sz];
          if(gzgets(file, uncompr, sz) < 0)
            goto exit;
          break;
        }
        case 9: {
          int level = dataLen ? (--dataLen, *data++) : 1;
          int strat = dataLen ? (--dataLen, *data++) : 2;
          if(gzsetparams(file, level, strat) < 0)
            goto exit;
          break;
        }
        case 10: {
          int flush = dataLen ? (--dataLen, *data++) : 1;
          gzflush(file, flush); break;
        }
        case 11: {
          static const char formats [][4] = { "%d", "%f", "%c", "%s" };
          int nformat = dataLen ? (--dataLen, *data++)%5 : 1;
          switch(nformat) {
            case 0: {
              int value = dataLen >= sizeof(int) ? *(int*)data : 1;
              gzprintf(file, formats[nformat], value);
              break;
            }
            case 1: {
              float value = dataLen >= sizeof(float) ? *(float*)data : 1;
              gzprintf(file, formats[nformat], value);
              break;
            }
            case 2: {
              char value = dataLen >= sizeof(char) ? *(char*)data : 1;
              gzprintf(file, formats[nformat], value);
              break;
            }
            case 3: {
             unsigned sz = dataLen ? ((--dataLen, *data++)&0xF)+1 : 8;
             char input[sz];
             memcpy(input, data, dataLen >= sz ? sz - 1: dataLen);
             input[sz - 1] = 0;
             gzprintf(file, formats[nformat], input);
             break;
            }
            default: {
             unsigned sz = dataLen ? ((--dataLen, *data++)&0xF)+1 : 8;
             char input[sz] = {};
             memcpy(input, data, dataLen >= sz ? sz - 1: dataLen);
             for(int i = 0; i < sz - 1; ++i)
               if(input[i] == '%') input[i] = '!';
             gzprintf(file, input);
             break;
            }
          };
          break;
        }
        case 12: {
          gzoffset(file);
          break;
        }
        case 13: {
          gzrewind(file);
          break;
        }
        case 14: {
          gzeof(file);
          break;
        }
        case 15: {
          gzdirect(file);
          break;
        }
        case 16: {
          unsigned sz = dataLen ? ((--dataLen, *data++))|1 : 128;
          if(gzbuffer(file, sz) <0)
            goto exit;
          break;
        }
        case 17: {
          int errnum;
          gzerror(file, &errnum);
          break;
        }
        case 18: {
          gzclearerr(file);
          break;
        }
      }
    }
    gzclose(file);
    remove(fname);
  return 0;
exit:
    gzclose(file);
    remove(fname);
  return -1;
}

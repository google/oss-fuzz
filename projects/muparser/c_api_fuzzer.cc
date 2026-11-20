/* Copyright 2026 Google LLC

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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>

#include "muParserDLL.h"

// Callbacks
muFloat_t MyFun1(muFloat_t v) { return v * 2; }
muFloat_t MyFun2(muFloat_t v1, muFloat_t v2) { return v1 + v2; }
muFloat_t MyInfixFun(muFloat_t v) { return -v; }
muFloat_t MyPostfixFun(muFloat_t v) { return v + 1; }
muFloat_t MyOprtFun(muFloat_t v1, muFloat_t v2) { return v1 * v2 + 1; }

muFloat_t* MyVarFactory(const muChar_t* name, void* pUserData) {
  static muFloat_t v[10];
  return v;
}

muInt_t MyIdentFun(const muChar_t* name, muInt_t* pos, muFloat_t* val) {
  if (strncmp(name, "test", 4) == 0) {
    *val = 123.0;
    *pos += 4;
    return 1;
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) return 0;

  // Use the first few bytes for configuration
  uint8_t config = data[0];
  uint8_t config2 = data[1];
  int base_type = (config & 0x01) ? muBASETYPE_INT : muBASETYPE_FLOAT;
  
  muParserHandle_t hParser = mupCreate(base_type);
  if (!hParser) return 0;

  // Remaining data as expression
  size_t expr_size = (size - 2) / 2;
  std::string expr((char *)(data + 2), expr_size);
  mupSetExpr(hParser, expr.c_str());

  std::string custom_chars((char *)(data + 2 + expr_size), size - 2 - expr_size);

  // Conditional configurations based on config bits
  if (config & 0x02) {
    mupDefineInfixOprt(hParser, "!", MyInfixFun, 0, 1);
  }
  if (config & 0x04) {
    mupDefinePostfixOprt(hParser, "!!", MyPostfixFun, 1);
  }
  if (config & 0x08) {
    mupDefineOprt(hParser, "shr", MyOprtFun, 0, muOPRT_ASCT_LEFT, 1);
  }
  if (config & 0x10) {
    mupSetVarFactory(hParser, MyVarFactory, NULL);
  }
  if (config & 0x20) {
    mupAddValIdent(hParser, MyIdentFun);
  }
  
  if (!custom_chars.empty()) {
    if (config & 0x40) {
      mupDefineNameChars(hParser, custom_chars.c_str());
    }
    if (config & 0x80) {
      mupDefineOprtChars(hParser, custom_chars.c_str());
    }
  }

  // Set some common things anyway
  muFloat_t v1[10] = {1.0};
  mupDefineVar(hParser, "v1", v1);
  mupDefineConst(hParser, "c1", 3.14);
  mupDefineStrConst(hParser, "s1", "hello");
  
  // From c_api_fuzzer.cc
  mupDefineFun1(hParser, "f1", MyFun1, 1);
  mupDefineFun2(hParser, "f2", MyFun2, 1);

  // Evaluate
  try {
    if (config2 & 0x01) {
      // Bulk mode evaluation
      muFloat_t results[10];
      mupEvalBulk(hParser, results, 10);
    } else {
      mupEval(hParser);
      
      // Try mupEvalMulti only if no error occurred in mupEval
      if (!mupError(hParser)) {
        int nNum;
        mupEvalMulti(hParser, &nNum);
      }
    }
  } catch (...) {
  }

  // Error handling
  if (mupError(hParser)) {
    mupGetErrorCode(hParser);
    mupGetErrorPos(hParser);
    mupGetErrorMsg(hParser);
    mupGetErrorToken(hParser);
  }

  mupRelease(hParser);
  return 0;
}

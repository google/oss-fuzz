// Copyright 2023 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

const { FuzzedDataProvider } = require('@jazzer.js/core');
const fs = require('fs');
global.nodePath = require('path');
global.assert = require('assert');

global.MEMORY64 = true;
global.EXPORT_ES6 = true;
global.USE_ES6_IMPORT_META = true;
global.WASM_BIGINT = false;

const LONG_LENGTH = 1024;
const SHORT_LENGTH = 128;
const TINY_LENGTH = 16;

global.find = (filename) => {
  const prefixes = [__dirname, process.cwd()];
  for (let i = 0; i < prefixes.length; ++i) {
    const combined = nodePath.join(prefixes[i], filename);
    if (fs.existsSync(combined)) {
      return combined;
    }
  }
  return filename;
}

global.read = (filename) => {
  const absolute = find(filename);
  return fs.readFileSync(absolute).toString();
};

global.printErr = (error) => {}

module.exports.fuzz = function (buffer) {
    const data = new FuzzedDataProvider(buffer);

    const i1 = data.consumeIntegralInRange(1, 9);
    const n1 = data.consumeNumber();
    const n2 = data.consumeNumber();

    const s1 = data.consumeString(LONG_LENGTH, 'utf-8', true);
    const s2 = data.consumeString(SHORT_LENGTH, 'utf-8', true);
    const s3 = data.consumeString(TINY_LENGTH, 'utf-8', true);

    try {
        switch(i1) {
            case 1:
                fs.writeFileSync("fuzzer-temp-file", s1);
                preprocess("fuzzer-temp-file");
                fs.unlinkSync("fuzzer-temp-file");
                break;
            case 2:
                makeInlineCalculation(s1, s2, s3);
                break;
            case 3:
                splitI64(s1);
                break;
            case 4:
                getHeapOffset(n1, s3);
                break;
            case 5:
                ensureDot(n1);
                break;
            case 6:
                asmEnsureFloat(n1, s3);
                break;
            case 7:
                asmCoercion(n1, s3);
                break;
            case 8:
                makeHEAPView(s1, n1, n2);
                break;
            case 9:
                calcFastOffset(n1, n2);
                break;
        }
    } catch(error) {
        if (!error.toString().includes("Unexpected end of input")) {
            throw error;
        }
    }
};

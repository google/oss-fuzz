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


const tar = require('tar');
const { FuzzedDataProvider } = require("@jazzer.js/core");

/**
 * @param { Buffer } fuzzerInputData
 */
module.exports.fuzz = function (fuzzerInputData) {
    const data = new FuzzedDataProvider(fuzzerInputData);
    try {
        const fileName = data.consumeString(data.consumeUInt8());
        const fileContent = data.consumeRemainingAsBuffer();

        tar.c({ gzip: data.consumeBool() }, [fileName]).then(buffer => {
            tar.x({ file: buffer });
        });
    } catch (error) {
        if (error instanceof TypeError) {
            return;
        }
    }
};

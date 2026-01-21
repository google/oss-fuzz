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
const MAX_LENGTH = 1024;
global.assert = require('assert');
const AssertionError = require('assert').AssertionError;

global.BOOTSTRAPPING_STRUCT_INFO = true;
global.ENVIRONMENT_IS_WASM_WORKER = false;

module.exports.fuzz = function (buffer) {
    const fdp = new FuzzedDataProvider(buffer);

    const i = fdp.consumeIntegralInRange(1, 4);
    const n = fdp.consumeNumber();
    const s = fdp.consumeString(MAX_LENGTH, 'utf-8', true);
    global.BOOTSTRAPPING_STRUCT_INFO = fdp.consumeBoolean();

    try {
        switch(i) {
            case 1:
                mangleCSymbolName(s);
                break;
            case 2:
                stringifyWithFunctions(s);
                break;
            case 3:
                stringifyWithFunctions(s);
                break;
            case 4:
                getTransitiveDeps(s);
                break;
        }
    } catch (error) {
        if (!error instanceof AssertionError) {
            throw error
        }
    }
};

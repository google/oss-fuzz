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
const jpeg = require("./index");

module.exports.fuzz = function (data) {
    const provider = new FuzzedDataProvider(data);

    try {
        jpeg.decode(provider.consumeBytes(provider.consumeIntegralInRange(0, 2**48-1)),
            {useTArray: provider.consumeBoolean(),
                colorTransform: provider.consumeBoolean(),
                formatAsRGBA: provider.consumeBoolean(),
                tolerantDecoding: provider.consumeBoolean()}
        );
    } catch (error) {
        // Catch all errors to find more critical bugs.
    }
};

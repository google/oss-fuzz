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

    var width = provider.consumeIntegralInRange(0, 2**48-1),
        height = provider.consumeIntegralInRange(0, 2**48-1),
        quality = provider.consumeIntegralInRange(0, 2**48-1);
    var frameData = provider.consumeRemainingAsBytes();
    var rawImageData = {
        data: frameData,
        width: width,
        height: height,
    };

    try {
        var jpegImageData = jpeg.encode(rawImageData, quality);
    } catch (error) {
        // Catch all errors to find critical bugs.
    }
};
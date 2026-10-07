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
const xml2js = require("./lib/xml2js");


module.exports.fuzz = async function (data) { // async? --sync will have oom
    const provider = new FuzzedDataProvider(data);
    let xml = provider.consumeString(provider.consumeIntegralInRange(0, 2**48-1));

    var options = {
        attrkey: provider.consumeString(provider.consumeIntegralInRange(0, 2**48-1)),
        charkey: provider.consumeString(provider.consumeIntegralInRange(0, 2**48-1)),
        explicitCharkey: provider.consumeBoolean(),
        trim: provider.consumeBoolean(),
        normalizeTags: provider.consumeBoolean(),
        normalize: provider.consumeBoolean(),
        explicitRoot: provider.consumeNumber(),
        emptyTag: provider.consumeString(provider.consumeIntegralInRange(0, 2**48-1)),
        explicitArray: provider.consumeBoolean(),
        ignoreAttrs: provider.consumeBoolean(),
        mergeAttrs: provider.consumeBoolean(),
        xmlns: provider.consumeBoolean(),
        explicitChildren: provider.consumeBoolean(),
        childkey: provider.consumeString(provider.consumeIntegralInRange(0, 2**48-1)),
        preserveChildrenOrder: provider.consumeBoolean(),
        charsAsChildren: provider.consumeBoolean(),
        includeWhiteChars: provider.consumeBoolean(),
        async: provider.consumeBoolean(),
        strict: provider.consumeBoolean(),
    };

    var parser = new xml2js.Parser(options);
    try {
        parser.parseString(xml);
        parser.parseStringPromise(xml).then(function () {}).catch(function () {});
    } catch (error) {
        // Catch expected errors to find more interesting bugs.
    }
};

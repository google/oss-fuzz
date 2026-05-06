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
//
////////////////////////////////////////////////////////////////////////////////

const { FuzzedDataProvider } = require('@jazzer.js/core');
const { parse } = require('@formatjs/icu-messageformat-parser');

module.exports.fuzz = function (data) {
  const fdp = new FuzzedDataProvider(data);

  const opts = {
    ignoreTag: fdp.consumeBoolean(),
    requiresOtherClause: fdp.consumeBoolean(),
    shouldParseSkeletons: fdp.consumeBoolean(),
    captureLocation: fdp.consumeBoolean(),
  };

  const message = fdp.consumeRemainingAsString();

  try {
    parse(message, opts);
  } catch (e) {
    if (!isExpectedParserError(e)) {
      throw e;
    }
  }
};

function isExpectedParserError(e) {
  // The parser throws SyntaxError on malformed ICU messages — that's the
  // documented contract. Anything else is interesting.
  return e instanceof SyntaxError;
}

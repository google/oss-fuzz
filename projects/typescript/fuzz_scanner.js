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
const ts = require('typescript');

module.exports.fuzz = function(data) {
  try {
    const provider = new FuzzedDataProvider(data);

    const languageVersion = provider.consumeIntegralInRange(0, 3);
    const skipTrivia = provider.consumeBoolean();
    const languageVariant = provider.consumeIntegralInRange(0, 2);
    const text = provider.consumeString(provider.consumeIntegralInRange(0, 10000));
    const onError = (_message) => { };
    const start = provider.consumeIntegralInRange(0, text.length);
    const length = provider.consumeIntegralInRange(0, text.length - start);

    const scanner = ts.createScanner(languageVersion, skipTrivia, languageVariant, text, onError, start, length);

    while (scanner.scan() !== ts.SyntaxKind.EndOfFileToken) {
      scanner.getToken();
      scanner.getTokenText();
      scanner.getTokenValue();
      scanner.getTokenStart();
      scanner.getTokenEnd();

      if (provider.remainingBytes > 0 && provider.consumeProbabilityFloat() < 0.1) {
        scanner.resetTokenState(provider.consumeIntegralInRange(0, text.length));
      }

    }
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.toLowerCase().indexOf(message) !== -1);
}

const ignored = [
  "expected",
  "unexpected",
  "invalid",
  "unterminated",
  "must be",
  "incorrect",
  "stream error",
  "duplicate",
  "the value"
];

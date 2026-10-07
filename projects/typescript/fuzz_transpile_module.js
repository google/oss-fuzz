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
const { getCompilerOptions } = require("./fuzz_util");
const ts = require('typescript');

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);
  const input = provider.consumeRemainingAsString();
  const transpileOptions = {
    getCompilerOptions: () => getCompilerOptions(provider),
  };

  try {
    ts.transpileModule(input, transpileOptions);
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.toLowerCase().indexOf(message) !== -1);
}

const ignored = [
  // TypeScript not interested: https://github.com/microsoft/TypeScript/issues/55480
  "maximum call stack size exceeded",
  "expected",
  "unexpected",
  "invalid",
  "cannot",
  "unterminated",
  "must be",
  "incorrect",
  "stream error",
  "duplicate",
  "the value"
];

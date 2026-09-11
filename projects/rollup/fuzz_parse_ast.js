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

const { FuzzedDataProvider } = require("@jazzer.js/core");
const { parseAst } = require("rollup/parseAst");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);

  const options = {
    allowReturnOutsideFunction: provider.consumeBoolean(),
    jsx: provider.consumeBoolean(),
  };

  const code = provider.consumeRemainingAsString();

  try {
    parseAst(code, options);
  } catch (error) {
    if (!isExpectedError(error)) {
      throw error;
    }
  }
};

function isExpectedError(error) {
  if (!error || typeof error.message !== "string") {
    return false;
  }
  const message = error.message.toLowerCase();
  // Rollup's parser throws structured PARSE_ERROR codes for invalid input.
  // These are expected for fuzzed (typically malformed) source code.
  if (error.code === "PARSE_ERROR") {
    return true;
  }
  return EXPECTED_MESSAGES.some((m) => message.includes(m));
}

const EXPECTED_MESSAGES = [
  "parse error",
  "unexpected",
  "unterminated",
  "invalid",
  "expected",
];

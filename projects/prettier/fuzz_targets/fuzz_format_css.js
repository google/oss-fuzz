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
const prettier = require("prettier");

const CSS_PARSERS = ["css", "scss", "less"];

module.exports.fuzz = async function (data) {
  const provider = new FuzzedDataProvider(data);
  const parser = CSS_PARSERS[provider.consumeIntegralInRange(0, CSS_PARSERS.length - 1)];
  const options = {
    parser,
    printWidth: provider.consumeIntegralInRange(0, 200),
    tabWidth: provider.consumeIntegralInRange(0, 8),
    useTabs: provider.consumeBoolean(),
    singleQuote: provider.consumeBoolean(),
    endOfLine: ["lf", "crlf", "cr", "auto"][provider.consumeIntegralInRange(0, 3)],
  };
  const source = provider.consumeRemainingAsString();

  try {
    await prettier.format(source, options);
  } catch (error) {
    if (!isExpectedError(error)) throw error;
  }
};

function isExpectedError(error) {
  if (error && error.name === "SyntaxError") return true;
  const msg = (error && error.message) || "";
  return EXPECTED.some((m) => msg.indexOf(m) !== -1);
}

const EXPECTED = [
  "Unknown word",
  "Unclosed",
  "Unclosed block",
  "Unclosed string",
  "Unclosed bracket",
  "Unexpected",
  "Invalid",
  "Missed semicolon",
  "Missing whitespace",
  "Double colon",
  "Unnecessary curly bracket",
  "Maximum call stack size exceeded",
];

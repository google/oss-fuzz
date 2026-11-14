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

const JS_PARSERS = [
  "babel",
  "babel-flow",
  "acorn",
  "espree",
  "meriyah",
  "flow",
];

module.exports.fuzz = async function (data) {
  const provider = new FuzzedDataProvider(data);
  const parser = JS_PARSERS[provider.consumeIntegralInRange(0, JS_PARSERS.length - 1)];
  const options = {
    parser,
    printWidth: provider.consumeIntegralInRange(0, 200),
    tabWidth: provider.consumeIntegralInRange(0, 8),
    useTabs: provider.consumeBoolean(),
    semi: provider.consumeBoolean(),
    singleQuote: provider.consumeBoolean(),
    bracketSpacing: provider.consumeBoolean(),
    bracketSameLine: provider.consumeBoolean(),
    arrowParens: provider.consumeBoolean() ? "always" : "avoid",
    trailingComma: ["all", "es5", "none"][provider.consumeIntegralInRange(0, 2)],
    quoteProps: ["as-needed", "consistent", "preserve"][
      provider.consumeIntegralInRange(0, 2)
    ],
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
  "Unexpected token",
  "Unexpected character",
  "Unterminated",
  "Unterminated string",
  "Unterminated template",
  "Unterminated comment",
  "Unterminated regular expression",
  "Invalid",
  "Identifier directly after number",
  "Identifier expected",
  "Expression expected",
  "Missing semicolon",
  "Cannot use import statement",
  "private name",
  "is reserved",
  "decimal escape",
  "Octal literal in strict mode",
  "Numeric separator",
  "Hexadecimal digit expected",
  "Bigint",
  "Comma is not permitted",
  "Trailing comma",
  "Stage 3",
  "experimental",
  "is not enabled",
  "Decorators",
  "Maximum call stack size exceeded",
];

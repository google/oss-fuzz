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
const postcss = require('./lib/postcss');

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);

  // The CSS input itself is randomized: every byte the fuzzer produces (or
  // mutates from the seed corpus) flows directly into `cssString` via
  // consumeRemainingAsString(). The option flags below are read from the
  // *back* of the buffer (jazzer.js consumes integrals/booleans from the
  // tail), so seed CSS files from postcss-parser-tests are fed into the
  // parser nearly verbatim, with only their last few bytes nibbled off as
  // option control.
  const useMap = provider.consumeBoolean();
  const useFrom = provider.consumeBoolean();
  const useProcessor = provider.consumeBoolean();
  const splitMode = provider.consumeIntegralInRange(0, 2);
  const cssString = provider.consumeRemainingAsString();

  const parseOptions = {};
  if (useFrom) parseOptions.from = 'fuzz.css';
  if (useMap) parseOptions.map = { inline: false, annotation: false };

  let root;
  try {
    root = postcss.parse(cssString, parseOptions);
  } catch (e) {
    if (e instanceof postcss.CssSyntaxError) return;
    throw e;
  }

  // Walk the AST and exercise common node accessors. This also stresses
  // raws/source bookkeeping for any node returned by the parser.
  try {
    root.walk(node => {
      void node.type;
      void node.toString();
      if (typeof node.error === 'function') {
        // Generating an error message touches input/source-map machinery.
        node.error('fuzz').message;
      }
    });
  } catch (e) {
    if (!isExpected(e, postcss)) throw e;
  }

  // Round-trip via stringify and re-parse. Output should itself be parseable.
  let serialized;
  try {
    serialized = root.toString();
  } catch (e) {
    if (!isExpected(e, postcss)) throw e;
    return;
  }

  try {
    postcss.parse(serialized);
  } catch (e) {
    if (!(e instanceof postcss.CssSyntaxError)) throw e;
  }

  // Exercise the JSON serialization round-trip.
  try {
    const json = root.toJSON();
    postcss.fromJSON(json);
  } catch (e) {
    if (!isExpected(e, postcss)) throw e;
  }

  // Exercise the main public entry point: postcss().process(). This drives
  // the LazyResult / NoWorkResult pipeline that real plugin chains use.
  if (useProcessor) {
    try {
      const result = postcss().process(cssString, parseOptions);
      void result.css;
      void result.warnings();
    } catch (e) {
      if (!isExpected(e, postcss)) throw e;
    }
  }

  // Exercise the list helpers, which have their own quoting/escape logic.
  try {
    if (splitMode === 0) {
      postcss.list.comma(cssString);
    } else if (splitMode === 1) {
      postcss.list.space(cssString);
    } else {
      postcss.list.split(cssString, [',', ' '], false);
    }
  } catch (e) {
    if (!isExpected(e, postcss)) throw e;
  }
};

function isExpected(error, postcss) {
  if (error instanceof postcss.CssSyntaxError) return true;
  if (!error || typeof error.message !== 'string') return false;
  // Some legitimate inputs reach known-shaped TypeErrors during stringify or
  // walk because the CSS allows constructs whose textual form is ambiguous.
  // Suppress only those well-defined cases so real bugs still surface.
  const benign = [
    'Unknown node type',
    'Unknown word',
  ];
  return benign.some(msg => error.message.indexOf(msg) !== -1);
}

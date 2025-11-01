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
const canvg = require('./dist/index.js');
const canvas = require('canvas');
const fetch = require("node-fetch-commonjs");
const { DOMParser } = require('xmldom');

const preset = canvg.presets.node({
  DOMParser,
  canvas,
  fetch
});

module.exports.fuzz = async function(data) {
  try {
    const provider = new FuzzedDataProvider(data);
    const func = provider.consumeIntegralInRange(0, 3);
    const canvasWidth = provider.consumeIntegralInRange(0, 9999);
    const canvasHeight = provider.consumeIntegralInRange(0, 9999);
    const svgStr = provider.consumeRemainingAsString();

    switch (func) {
      case 0:
        const canvas = preset.createCanvas(canvasWidth, canvasHeight);
        const ctx = canvas.getContext('2d');
        const svg = canvg.Canvg.fromString(ctx, svgStr, preset);
        await svg.render();
        canvas.toBuffer();
        break;
      case 1:
        const parser = new canvg.Parser({ DOMParser: DOMParser });
        parser.parse(svgStr);
        break;
      case 2:
        const canvgInstance = new canvg.Canvg('', svgStr, preset);
        canvgInstance.start();
        canvgInstance.stop();
        break;
      case 3:
        const canvgInstance2 = new canvg.Canvg('', svgStr, preset);
        canvgInstance2.start();
        await new Promise(resolve => setTimeout(resolve, 1000));
        canvgInstance2.stop();
        break;
    }

  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  "Cannot read properties",
  "Cannot set properties",
  "Attribute class redefined",
  "Expected positive number",
  "Unterminated command",
  "Unexpected character",
  "Attribute height redefined",
  "Attribute",
  "Invalid number ending",
  "Expected a flag",
  "end tag name",
];


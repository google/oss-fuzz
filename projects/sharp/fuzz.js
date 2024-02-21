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

const sharp = require('./lib/index');
const { FuzzedDataProvider } = require('@jazzer.js/core');

module.exports.fuzz = async function(data) {
  const provider = new FuzzedDataProvider(data);

  try {
    const options = {
      failOn: pickFromArray(["none", "truncated", "error", "warning", provider.consumeString(provider.consumeIntegralInRange(0, 64))]),
      limitInputPixels: provider.consumeIntegralInRange(1, 2 ** 28),
      unlimited: provider.consumeBoolean(),
      sequentialRead: provider.consumeBoolean(),
      density: provider.consumeIntegralInRange(1, 100001),
      ignoreicc: provider.consumeBoolean(),
      pages: provider.consumeIntegrals(provider.consumeIntegralInRange(1, 10), provider.consumeIntegralInRange(1, 2), provider.consumeBoolean()).push(-1),
      page: provider.consumeIntegralInRange(1, 1000),
      subifd: provider.consumeIntegralInRange(-1, 1000),
      level: provider.consumeIntegralInRange(0, 1000),
      animated: provider.consumeBoolean(),
    };
    const width = provider.consumeIntegralInRange(1, 10000);
    const height = provider.consumeIntegralInRange(1, 10000);
    const gravity = provider.consumeString(provider.consumeIntegralInRange(0, 1000));
    const top = provider.consumeIntegralInRange(1, 1000);
    const bottom = provider.consumeIntegralInRange(1, 1000);
    const left = provider.consumeIntegralInRange(1, 1000);
    const right = provider.consumeIntegralInRange(1, 1000);
    const background = provider.consumeString(provider.consumeIntegralInRange(0, 1000));
    const withMeta = provider.consumeBoolean();
    const degrees = provider.consumeIntegralInRange(0, 361);
    const gamma = provider.consumeFloatInRange(0.0, 4.0);
    var input = "";
    if (provider.consumeBoolean() == true) {
      input = Buffer.from(provider.consumeBytes(provider.consumeIntegralInRange(1, 100000)));
    } else {
      input = Buffer.from(provider.consumeRemainingAsBytes());
    }
    if (input.length == 0) {
      return;
    }


    switch (provider.consumeIntegralInRange(0, 20)) {
      case 0:
        sharp(input)
          .rotate(degrees)
          .toBuffer((_err, _out) => { });
        break;
      case 1:
        sharp(input)
          .flip()
          .toBuffer((_err, _out) => { });
        break;
      case 2:
        sharp(input)
          .flop()
          .toBuffer((_err, _out) => { });
        break;
      case 3:
        sharp(input)
          .grayscale()
          .toBuffer((_err, _out) => { });
        break;
      case 4:
        sharp(input, options)
          .composite([{ input: input, gravity: gravity }], options)
          .toBuffer((_err, _out) => { });
        break;
      case 5:
        sharp(input, options)
          .extend({ top: top, bottom: bottom, left: left, right: right, background: background }, options)
          .toBuffer((_err, _out) => { });
        break;
      case 6:
        sharp(input, options)
          .trim(options)
          .toBuffer((_err, _out) => { });
        break;
      case 7:
        sharp(input, options)
          .median(options)
          .toBuffer((_err, _out) => { });
        break;
      case 8:
        sharp(input, options)
          .unflatten(options)
          .toBuffer((_err, _out) => { });
        break;
      case 9:
        sharp(input, options)
          .flatten(options)
          .toBuffer((_err, _out) => { });
        break;
      case 10:
        sharp(input, options)
          .gamma(gamma)
          .toBuffer((_err, _out) => { });
        break;
      case 11:
        sharp(input, options)
          .gif(options)
          .toBuffer((_err, _out) => { });
        break;
      case 12:
        sharp(input, options)
          .clahe(options)
          .toBuffer((_err, _out) => { });
        break;
      case 13:
        //console.log(`case 13`);
        sharp(input, options)
          .withMetadata(withMeta)
          .toBuffer((_err, _out) => { });
        break;
      case 14:
        sharp(input, options)
          .jpeg(options)
          .toBuffer((_err, _out) => { });
        break;
      case 15:
        sharp(input, options)
          .png(options)
          .toBuffer((_err, _out) => { });
        break;
      case 16:
        sharp(input, options)
          .webp(options)
          .toBuffer((_err, _out) => { });
        break;
      case 17:
        sharp(input, options)
          .tiff(options)
          .toBuffer((_err, _out) => { });
        break;
      case 18:
        sharp(input, options)
          .avif(options)
          .toBuffer((_err, _out) => { });
        break;
      case 19:
        sharp(input, options)
          .negate(options)
          .toBuffer((_err, _out) => { });
        break;
      case 20:
        sharp(input)
          .resize(width, height)
          .toBuffer((_err, _out) => { });
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
  "Input Buffer is empty",
  "Expected valid gravity",
  "Expected one of:",
  "Expected integer",
  "Expected number",
  "Expected object or string",
  "Unable to parse",
];


function pickFromArray(array) {
  return array[Math.floor(Math.random() * array.length)];
}

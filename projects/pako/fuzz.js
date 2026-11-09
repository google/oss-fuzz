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

const pako = require('pako');
const { FuzzedDataProvider } = require('@jazzer.js/core');

module.exports.fuzz = function(data) {
  const fdp = new FuzzedDataProvider(data);
  const choice = fdp.consumeBoolean();

  try {
    if (choice === true) {
      const comprLevel = fdp.consumeIntegralInRange(0, 9); // Valid compression levels: 0-9
      const windowBits = fdp.consumeIntegralInRange(8, 15); // Valid window bits
      const memLevel = fdp.consumeIntegralInRange(1, 9); // Valid memory levels
      const strategy = fdp.consumeIntegralInRange(0, 4); // Valid strategies
      const raw = fdp.consumeBoolean();
      const input = fdp.consumeRemainingAsBytes();
      const options = {
        level: comprLevel,
        windowBits: windowBits,
        memLevel: memLevel,
        strategy: strategy,
        raw: raw
      };

      // Compress and decompress with deflate and inflate
      const defl = pako.deflate(input, options);
      const decompressed = pako.inflate(defl, options);

      // Validate the output matches the input
      if (!arraysEqual(decompressed, input)) {
        throw new Error('Decompressed data does not match original input');
      }

      // Test deflateRaw and inflateRaw
      const deflRaw = pako.deflateRaw(input, options);
      const decompressedRaw = pako.inflateRaw(deflRaw, options);
      if (!arraysEqual(decompressedRaw, input)) {
        throw new Error('Decompressed raw data does not match original input');
      }

    } else {
      // Generate random and edge-case options for gzip
      const gzipOptions = {
        level: fdp.consumeIntegralInRange(0, 9),
        raw: fdp.consumeBoolean(),
        to: fdp.consumeString(10),
        windowBits: fdp.consumeIntegralInRange(8, 15),
        memLevel: fdp.consumeIntegralInRange(1, 9),
        strategy: fdp.consumeIntegralInRange(0, 4),
        header: {
          text: fdp.consumeBoolean(),
          time: fdp.consumeIntegral(),
          os: fdp.consumeIntegralInRange(0, 255),
          extra: fdp.consumeRemainingAsBytes()
        }
      };
      const input = fdp.consumeRemainingAsBytes();

      // Compress and decompress with gzip and ungzip
      const gzip = pako.gzip(input, gzipOptions);
      const decompressedGzip = pako.ungzip(gzip, gzipOptions);
      if (!arraysEqual(decompressedGzip, input)) {
        throw new Error('Decompressed gzip data does not match original input');
      }

      // Test inflate and inflateRaw
      pako.inflate(gzip);
      pako.inflateRaw(gzip);
    }
  } catch (error) {
    if (error.message && !ignoredError(error)) {
      console.error('Unhandled error:', error.message);
      throw error;
    }
  }
};

// Helper function to compare byte arrays
function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Define ignored errors to avoid unnecessary crashes
function ignoredError(error) {
  console.error('Error encountered:', error.message);
  return !!ignored.find((message) => error.message.includes(message));
}

// List of errors to ignore
const ignored = [
  'stream error',
  'invalid window size',
  'incorrect header check'
];

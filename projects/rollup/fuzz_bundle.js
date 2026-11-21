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
const { rollup } = require("rollup");

const FORMATS = ["amd", "cjs", "es", "iife", "system", "umd"];
const GENERATED_CODE = ["es5", "es2015"];

function virtualPlugin(entryCode) {
  return {
    name: "virtual-entry",
    resolveId(source) {
      if (source === "entry.js") {
        return source;
      }
      // Mark every other import as external so we don't touch the real
      // filesystem while still exercising import-resolution code paths.
      return { id: source, external: true };
    },
    load(id) {
      if (id === "entry.js") {
        return entryCode;
      }
      return null;
    },
  };
}

module.exports.fuzz = async function (data) {
  const provider = new FuzzedDataProvider(data);

  const inputOptions = {
    input: "entry.js",
    plugins: [virtualPlugin(provider.consumeString(provider.consumeIntegralInRange(0, 4096)))],
    onLog: () => {},
    treeshake: provider.consumeBoolean(),
  };

  const outputOptions = {
    format: FORMATS[provider.consumeIntegralInRange(0, FORMATS.length - 1)],
    name: provider.consumeString(provider.consumeIntegralInRange(0, 32)),
    generatedCode:
      GENERATED_CODE[provider.consumeIntegralInRange(0, GENERATED_CODE.length - 1)],
    compact: provider.consumeBoolean(),
    sourcemap: provider.consumeBoolean(),
    strict: provider.consumeBoolean(),
    esModule: provider.consumeBoolean(),
  };

  let bundle;
  try {
    bundle = await rollup(inputOptions);
    await bundle.generate(outputOptions);
  } catch (error) {
    if (!isExpectedBundleError(error)) {
      throw error;
    }
  } finally {
    if (bundle) {
      try {
        await bundle.close();
      } catch (_) {
        // ignore close errors
      }
    }
  }
};

function isExpectedBundleError(error) {
  if (!error) {
    return false;
  }
  if (typeof error.code === "string" && EXPECTED_CODES.has(error.code)) {
    return true;
  }
  const message =
    typeof error.message === "string" ? error.message.toLowerCase() : "";
  return EXPECTED_MESSAGES.some((m) => message.includes(m));
}

// Rollup raises these structured error codes for malformed or unsupported
// input; they are expected when fuzzing arbitrary source code and option
// combinations.
const EXPECTED_CODES = new Set([
  "PARSE_ERROR",
  "UNRESOLVED_IMPORT",
  "MISSING_EXPORT",
  "INVALID_OPTION",
  "INVALID_EXPORT_OPTION",
  "VALIDATION_ERROR",
  "MISSING_NAME_OPTION_FOR_IIFE_EXPORT",
  "MISSING_NAME_OPTION_FOR_UMD_EXPORT",
  "MIXED_EXPORTS",
  "AMBIGUOUS_EXTERNAL_NAMESPACES",
  "INVALID_EXTERNAL_ID",
  "MODULE_LEVEL_DIRECTIVE",
  "INVALID_PLUGIN_HOOK",
  "ILLEGAL_REASSIGNMENT",
  "ILLEGAL_IDENTIFIER_AS_NAME",
  "BAD_LOADER",
  "ASSET_NOT_FINALISED",
  "CHUNK_NOT_GENERATED",
  "FILE_NAME_CONFLICT",
  "INVALID_CONFIG_MODULE_FORMAT",
  "INPUT_HOOK_IN_OUTPUT_PLUGIN",
  "PLUGIN_ERROR",
]);

const EXPECTED_MESSAGES = [
  "parse error",
  "unexpected",
  "unterminated",
  "must be supplied",
  "invalid value",
  "is not exported",
  "could not resolve",
  "is not a valid",
  "exports is not specified",
  "you must supply",
];

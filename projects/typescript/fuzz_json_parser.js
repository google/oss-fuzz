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

    const fileContent = provider.consumeString(provider.consumeIntegralInRange(1, 10000));
    const host = createHost(provider);
    const basePath = provider.consumeString(provider.consumeIntegralInRange(1, 100));
    const existingOptions = createExistingOptions(provider);
    const configFileName = provider.consumeString(provider.consumeIntegralInRange(1, 100));

    const json = JSON.parse(fileContent);
    ts.parseJsonConfigFileContent(
      json,
      host,
      basePath,
      existingOptions,
      configFileName
    );
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.toLowerCase().indexOf(message) !== -1);
}

function createHost(provider) {
  return {
    fileExists: (fileName) => provider.consumeBoolean(),
    readFile: (fileName) => null,
    readDirectory: (path, extensions, exclude, include, depth) => [],
    getCurrentDirectory: () => process.cwd(),
    getDirectories: (path) => [],
    useCaseSensitiveFileNames: () => provider.consumeBoolean(),
    getCanonicalFileName: (fileName) => fileName,
    getNewLine: () => ts.sys.newLine,
    getDefaultLibFileName: (options) => ts.getDefaultLibFilePath(options),
    writeFile: (fileName, data) => { },
    resolveModuleNames: (moduleNames, containingFile, reusedNames, redirectedReference) => [],
    createHash: (data) => ts.createHash(data),
  };
}

function createExistingOptions(provider) {
  return {
    target: provider.consumeIntegralInRange(ts.ScriptTarget.ES3, ts.ScriptTarget.Latest),
    module: provider.consumeIntegralInRange(ts.ModuleKind.None, ts.ModuleKind.NodeNext),
    strict: provider.consumeBoolean(),
  };
}

const ignored = [
  "cannot read",
  "cannot create",
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

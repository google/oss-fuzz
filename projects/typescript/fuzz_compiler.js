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

const { FuzzedDataProvider } = require("@jazzer.js/core");
const { getCompilerOptions } = require("./fuzz_util");
const ts = require("typescript");

module.exports.fuzz = function(data) {
  const provider = new FuzzedDataProvider(data);

  try {
    const fileName = provider.consumeString(10) + ".ts";
    const fileContent = provider.consumeString(provider.consumeIntegralInRange(1, 10000));

    const sourceFile = ts.createSourceFile(fileName, fileContent, ts.ScriptTarget.Latest);
    const compilerOptions = getCompilerOptions(provider);

    const program = ts.createProgram([fileName], compilerOptions);
    const printer = ts.createPrinter();

    ts.createSourceMapSource(sourceFile.fileName, fileContent, provider.consumeBoolean());
    printer.printFile(sourceFile);
    const watchOptions = getWatchOptions(provider);

    ts.createWatchCompilerHost([fileName] /* rootFiles */, compilerOptions /* compilerOptions */,
      ts.sys /* System */, ts.createSemanticDiagnosticsBuilderProgram /* createProgram */,
      undefined /* DiagnosticReporter */, undefined, undefined, watchOptions /* watchOptions */);

    program.getTypeChecker();
    program.emit();
    ts.getParsedCommandLineOfConfigFile(fileName, {}, ts.sys).errors;
    program.getDeclarationDiagnostics();
  }
  catch (error) {
    if (!ignoredError(error)) {
      throw error;
    }
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.toLowerCase().indexOf(message) !== -1);
}

const ignored = [
  // TypeScript not interested: https://github.com/microsoft/TypeScript/issues/55480
  "maximum call stack size exceeded",
  "host.onunrecoverableconfigfilediagnostic is not a function", // weird bug
];

function getWatchOptions(provider) {
  return {
    watchFile: getWatchFileKind(provider),
    watchDirectory: getWatchDirectoryKind(provider),
    fallbackPolling: getFallbackPollingKind(provider),
    synchronousWatchDirectory: provider.consumeBoolean(),
    excludeDirectories: [],
    excludeFiles: [],
  }
}

function getWatchFileKind(provider) {
  switch (provider.consumeIntegralInRange(0, 6)) {
    case 0: return ts.WatchFileKind.FixedPollingInterval;
    case 1: return ts.WatchFileKind.PriorityPollingInterval;
    case 2: return ts.WatchFileKind.DynamicPriorityPolling;
    case 3: return ts.WatchFileKind.UseFsEvents;
    case 4: return ts.WatchFileKind.UseFsEventsOnParentDirectory;
    case 5: return ts.WatchFileKind.FixedChunkSizePolling;
    case 6: return provider.consumeString(provider.consumeIntegralInRange(0, 100));
  }
}

function getWatchDirectoryKind(provider) {
  switch (provider.consumeIntegralInRange(0, 4)) {
    case 0: return ts.WatchDirectoryKind.UseFsEvents;
    case 1: return ts.WatchDirectoryKind.FixedChunkSizePolling;
    case 2: return ts.WatchDirectoryKind.DynamicPriorityPolling;
    case 3: return ts.WatchDirectoryKind.FixedPollingInterval;
    case 4: return provider.consumeString(provider.consumeIntegralInRange(0, 100));
  }
}

function getFallbackPollingKind(provider) {
  switch (provider.consumeIntegralInRange(0, 4)) {
    case 0: return ts.PollingWatchKind.FixedInterval;
    case 1: return ts.PollingWatchKind.PriorityInterval;
    case 2: return ts.PollingWatchKind.DynamicPriority;
    case 3: return ts.PollingWatchKind.FixedChunkSize;
    case 4: return provider.consumeString(provider.consumeIntegralInRange(0, 100));
  }
}


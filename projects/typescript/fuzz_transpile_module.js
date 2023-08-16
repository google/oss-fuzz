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
  const provider = new FuzzedDataProvider(data);
  const input = provider.consumeRemainingAsString();
  const transpileOptions = {
    getCompilerOptions: () => getCompilerOptions(provider),
  };

  try {
    ts.transpileModule(input, transpileOptions);
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find((message) => error.message.toLowerCase().indexOf(message) !== -1);
}

function getCompilerOptions(provider) {
  return {
    allowJs: provider.consumeBoolean(),
    allowSyntheticDefaultImports: provider.consumeBoolean(),
    allowUnreachableCode: provider.consumeBoolean(),
    allowUnusedLabels: provider.consumeBoolean(),
    alwaysStrict: provider.consumeBoolean(),
    baseUrl: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    charset: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    checkJs: provider.consumeBoolean(),
    declaration: provider.consumeBoolean(),
    declarationDir: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    disableSizeLimit: provider.consumeBoolean(),
    downlevelIteration: provider.consumeBoolean(),
    emitBOM: provider.consumeBoolean(),
    emitDecoratorMetadata: provider.consumeBoolean(),
    experimentalDecorators: provider.consumeBoolean(),
    forceConsistentCasingInFileNames: provider.consumeBoolean(),
    importHelpers: provider.consumeBoolean(),
    inlineSourceMap: provider.consumeBoolean(),
    inlineSources: provider.consumeBoolean(),
    isolatedModules: provider.consumeBoolean(),
    jsx: getJsx(provider),
    lib: [],
    locale: provider.consumeString(provider.consumeIntegralInRange(0, 8)),
    mapRoot: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    maxNodeModuleJsDepth: provider.consumeIntegralInRange(0, 100),
    module: getModuleKind(provider),
    moduleResolution: getModuleResolutionKind(provider),
    newLine: provider.consumeBoolean() ? ts.NewLineKind.LineFeed : ts.NewLineKind.CarriageReturnLineFeed,
    noEmit: provider.consumeBoolean(),
    noEmitHelpers: provider.consumeBoolean(),
    noEmitOnError: provider.consumeBoolean(),
    noErrorTruncation: provider.consumeBoolean(),
    noFallthroughCasesInSwitch: provider.consumeBoolean(),
    noImplicitAny: provider.consumeBoolean(),
    noImplicitReturns: provider.consumeBoolean(),
    noImplicitThis: provider.consumeBoolean(),
    noUnusedLocals: provider.consumeBoolean(),
    noUnusedParameters: provider.consumeBoolean(),
    noImplicitUseStrict: provider.consumeBoolean(),
    noLib: provider.consumeBoolean(),
    noResolve: provider.consumeBoolean(),
    out: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    outDir: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    outFile: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    paths: {},
    plugins: [],
    preserveConstEnums: provider.consumeBoolean(),
    preserveSymlinks: provider.consumeBoolean(),
    project: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    reactNamespace: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    removeComments: provider.consumeBoolean(),
    references: [],
    rootDir: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    rootDirs: [],
    skipLibCheck: provider.consumeBoolean(),
    skipDefaultLibCheck: provider.consumeBoolean(),
    sourceMap: provider.consumeBoolean(),
    sourceRoot: provider.consumeString(provider.consumeIntegralInRange(0, 100)),
    strict: provider.consumeBoolean(),
    strictNullChecks: provider.consumeBoolean(),
    suppressExcessPropertyErrors: provider.consumeBoolean(),
    suppressImplicitAnyIndexErrors: provider.consumeBoolean(),
    useDefineForClassFields: provider.consumeBoolean(),
    target: getScriptTarget(provider),
    traceResolution: provider.consumeBoolean(),
    resolveJsonModule: provider.consumeBoolean(),
    types: [],
    typeRoots: []
  }
}

function getJsx(provider) {
  switch (provider.consumeIntegralInRange(0, 3)) {
    case 0: return ts.JsxEmit.None;
    case 1: return ts.JsxEmit.Preserve;
    case 2: return ts.JsxEmit.ReactNative;
    case 3: return ts.JsxEmit.React;
  }
}

function getModuleKind(provider) {
  switch (provider.consumeIntegralInRange(0, 10)) {
    case 0: return ts.ModuleKind.None;
    case 1: return ts.ModuleKind.CommonJS;
    case 2: return ts.ModuleKind.AMD;
    case 3: return ts.ModuleKind.UMD;
    case 4: return ts.ModuleKind.System;
    case 5: return ts.ModuleKind.ES2015;
    case 6: return ts.ModuleKind.ES2020;
    case 7: return ts.ModuleKind.ES2022;
    case 8: return ts.ModuleKind.ESNext;
    case 9: return ts.ModuleKind.Node16;
    case 10: return ts.ModuleKind.NodeNext;
  }
}

function getModuleResolutionKind(provider) {
  switch (provider.consumeIntegralInRange(0, 5)) {
    case 0: return ts.ModuleResolutionKind.Classic;
    case 1: return ts.ModuleResolutionKind.NodeNext;
    case 2: return ts.ModuleResolutionKind.Node16
    case 3: return ts.ModuleResolutionKind.Node10;
    case 4: return ts.ModuleResolutionKind.Bundler;
  }
}

function getScriptTarget(provider) {
  switch (provider.consumeIntegralInRange(0, 10)) {
    case 0: return ts.ScriptTarget.ESNext;
    case 1: return ts.ScriptTarget.ES2022;
    case 2: return ts.ScriptTarget.Latest;
    case 3: return ts.ScriptTarget.ES3;
    case 4: return ts.ScriptTarget.ES5;
    case 5: return ts.ScriptTarget.ESNext;
    case 6: return ts.ScriptTarget.JSON;
    case 7: return ts.ScriptTarget.ES2015;
    case 8: return ts.ScriptTarget.ES2016;
    case 9: return ts.ScriptTarget.ES2017;
  }
}

const ignored = [
  "expected",
  "unexpected",
  "invalid",
  "cannot",
  "unterminated",
  "must be",
  "incorrect",
  "stream error",
  "duplicate",
  "the value"
];


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

module.exports.fuzz = async function(data) {
  const provider = new FuzzedDataProvider(data);

  try {
    const fileName = provider.consumeString(10) + ".ts";
    const fileContents = provider.consumeString(1000);

    const sourceFile = ts.createSourceFile(
      fileName,
      fileContents,
      ts.ScriptTarget.Latest,
      /*setParentNodes */ true
    );

    ts.getPreEmitDiagnostics(sourceFile);
    ts.getTypeChecker(sourceFile);

    const shouldRemoveNode = provider.consumeBoolean();
    if (shouldRemoveNode) {
      const nodes = [];
      ts.forEachChild(sourceFile, node => nodes.push(node));
      if (nodes.length > 0) {
        const indexToRemove = provider.consumeIntegralInRange(0, nodes.length - 1);
        const nodeToRemove = nodes[indexToRemove];
        ts.removeNode(nodeToRemove);
      }
    }

    const shouldAddNode = provider.consumeBoolean();
    if (shouldAddNode) {
      const newNode = ts.createEmptyStatement();
      const nodes = [];
      ts.forEachChild(sourceFile, node => nodes.push(node));
      if (nodes.length > 0) {
        const indexToAddAt = provider.consumeIntegralInRange(0, nodes.length - 1);
        const nodeToAddAt = nodes[indexToAddAt];
        ts.insertNodeAtPosition(sourceFile, newNode, nodeToAddAt.pos);
      } else {
        ts.addSyntheticLeadingComment(sourceFile, ts.SyntaxKind.SingleLineCommentTrivia, 'Empty file', true);
        ts.addSyntheticTrailingComment(sourceFile, ts.SyntaxKind.SingleLineCommentTrivia, 'End of file', true);
      }
    }

    const numNodes = provider.consumeIntegral(1, true);
    for (let i = 0; i < numNodes; i++) {
      const nodes = [];
      ts.forEachChild(sourceFile, node => nodes.push(node));
      if (nodes.length > 0) {
        const indexToReplace = provider.consumeIntegralInRange(0, nodes.length - 1);
        const nodeToReplace = nodes[indexToReplace];
        const newNode = ts.createEmptyStatement();
        ts.replaceNode(nodeToReplace, newNode);
      }
    }

    const transformed = ts.transform(sourceFile, [/* transformation functions */]);
    transformed.transformed[0];

    const shouldFuzzLanguageFeature = provider.consumeBoolean();
    if (shouldFuzzLanguageFeature) {
      const classDeclaration = ts.createClassDeclaration(
        /* decorators */[],
        /* modifiers */[],
        provider.consumeString(10),
        /* typeParameters */[],
        /* heritageClauses */[],
        /* members */[]
      );
      ts.addDeclaration(sourceFile, classDeclaration);

      const interfaceDeclaration = ts.createInterfaceDeclaration(
        /* decorators */[],
        /* modifiers */[],
        provider.consumeString(10),
        /* typeParameters */[],
        /* heritageClauses */[],
        /* members */[]
      );
      ts.addDeclaration(sourceFile, interfaceDeclaration);

      const moduleDeclaration = ts.createModuleDeclaration(
        /* decorators */[],
        /* modifiers */[],
        ts.createIdentifier(provider.consumeString(10)),
        ts.createModuleBlock([]),
        ts.NodeFlags.Namespace
      );
      ts.addDeclaration(sourceFile, moduleDeclaration);

      const genericFunctionDeclaration = ts.createFunctionDeclaration(
        /* decorators */[],
        /* modifiers */[],
        /* asteriskToken */ undefined,
        provider.consumeString(10),
        /* typeParameters */[
          ts.createTypeParameterDeclaration(
            ts.createIdentifier(provider.consumeString(10)),
            /* constraint */ undefined,
            /* defaultType */ undefined
          )
        ],
        /* parameters */[],
        /* type */ undefined,
        /* body */ undefined
      );
      ts.addDeclaration(sourceFile, genericFunctionDeclaration);

      const decorator = ts.createDecorator(
        ts.createCall(
          ts.createIdentifier(provider.consumeString(10)),
          /* typeArguments */[],
          /* argumentsArray */[]
        )
      );
      ts.addDeclaration(sourceFile, decorator);

      const asyncFunctionDeclaration = ts.createFunctionDeclaration(
        /* decorators */[],
        /* modifiers */[],
        /* asteriskToken */ undefined,
        provider.consumeString(10),
        /* typeParameters */[],
        /* parameters */[],
        /* type */ undefined,
        ts.createBlock([
          ts.createAwaitExpression(
            ts.createCall(
              ts.createIdentifier(provider.consumeString(10)),
              /* typeArguments */[],
              /* argumentsArray */[]
            )
          )
        ])
      );
      ts.addDeclaration(sourceFile, asyncFunctionDeclaration);
    }

    const compilerOptions = getCompilerOptions(provider);
    const program = ts.createProgram([fileName], compilerOptions);
    program.emit();

    const shouldFuzzApiFunction = provider.consumeBoolean();
    if (shouldFuzzApiFunction) {
      const typeChecker = program.getTypeChecker();
      const randomSymbol = typeChecker.getSymbolAtLocation(sourceFile);
      typeChecker.getTypeOfSymbolAtLocation(randomSymbol, sourceFile);
    }

  } catch (error) {
    if (!ignoredError(error)) throw error;
  }
};

function ignoredError(error) {
  return !!ignored.find(message => error.message.toLowerCase().indexOf(message) !== -1);
}

const ignored = [
  // TypeScript not interested: https://github.com/microsoft/TypeScript/issues/55480
  "maximum call stack size exceeded",
];

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

  try {
    const fileName = provider.consumeString(10) + '.ts';
    const fileContents = provider.consumeString(1000);

    // Parse the source file
    const sourceFile = ts.createSourceFile(
      fileName,
      fileContents,
      ts.ScriptTarget.Latest,
      /*setParentNodes */ true
    );

    // Get the diagnostics for the source file
    ts.getPreEmitDiagnostics(sourceFile);

    // Consume a boolean and use it to randomly remove a node from the AST
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

    // Consume a boolean and use it to randomly add a new node to the AST
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

    // Consume an integral and use it to randomly replace a node in the AST
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
  } catch (error) {
    if (!ignoredError(error)) throw error;
  }

};
function ignoredError(error) {
  return !!ignored.find((message) => error.message.indexOf(message) !== -1);
}

const ignored = [
  "is not a function"
];


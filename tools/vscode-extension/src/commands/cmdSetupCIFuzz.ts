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

import * as vscode from 'vscode';
import {println} from '../logger';
import {determineWorkspaceLanguage} from '../utils';
import {cifuzzGenerator} from '../cifuzz';

export async function setupCIFuzzHandler() {
  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return false;
  }

  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

  /**
   * Go through GitHub workflows to find potential traces of CIFuzz
   */
  const githubWorkflowsPath = vscode.Uri.file(wsPath + '/.github/workflows');
  try {
    await vscode.workspace.fs.readDirectory(githubWorkflowsPath);
  } catch {
    println('Did not find a workflows path.');
    return false;
  }

  for (const [name, type] of await vscode.workspace.fs.readDirectory(
    githubWorkflowsPath
  )) {
    // Skip directories.
    if (type === 2) {
      continue;
    }

    // Read the files.
    println('Is a file');
    const workflowFile = vscode.Uri.file(wsPath + '/.github/workflows/' + name);
    const doc = await vscode.workspace.openTextDocument(workflowFile);
    if (doc.getText().includes('cifuzz')) {
      println('Found existing CIFuzz, will not continue.');
      return false;
    }
  }

  println('Did not find CIFuzz, creating one.');
  const projectName = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'OSS-Fuzz project name',
  });
  if (!projectName) {
    println('Failed to get project name');
    return false;
  }

  /*
   * There is no CIFuzz found, so we create one.
   */
  // Determine the language of the workspace.
  const targetLanguage = await determineWorkspaceLanguage();
  println('Target language: ' + targetLanguage);

  // Generate a CIFuzz workflow text.
  const cifuzzWorkflowText = cifuzzGenerator(targetLanguage, projectName, 30);

  // Create the CIFuzz .yml file and write the contents to it to path
  // .github/workflows/cifuzz.yml
  const cifuzzYml = vscode.Uri.file(wsPath + '/.github/workflows/cifuzz.yml');
  const wsedit = new vscode.WorkspaceEdit();
  wsedit.createFile(cifuzzYml, {ignoreIfExists: true});
  wsedit.insert(cifuzzYml, new vscode.Position(0, 0), cifuzzWorkflowText);
  vscode.workspace.applyEdit(wsedit);
  return true;
}

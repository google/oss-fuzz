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

import path = require('path');
import * as vscode from 'vscode';
import {println} from '../logger';
import {
  runFuzzerHandlerCFLite,
  buildFuzzersFromWorkspaceClusterfuzzLite,
} from '../ossfuzzWrappers';
import {setStatusText} from '../utils';
import {commandHistory} from '../commandUtils';
import {extensionConfig} from '../config';

/**
 * Does an end-to-end test of a project/fuzzer. This is done by
 * first building the project and then running the fuzzer.
 * @param context
 * @returns
 */

export async function cmdInputCollectorTestFuzzerCFLite() {
  setStatusText('Testing specific fuzzer: getting input');
  // Get the fuzzer to run
  const fuzzerNameInput = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Type a fuzzer name',
  });
  if (!fuzzerNameInput) {
    println('Failed to get fuzzer name');
    return;
  }

  // Create the args object for the dispatcher
  const args = new Object({
    fuzzerName: fuzzerNameInput.toString(),
  });

  // Create a dispatcher object.
  const commandObject = new Object({
    commandType: 'oss-fuzz.TestFuzzerCFLite',
    Arguments: args,
    dispatcherFunc: cmdDispatchTestFuzzerHandlerCFLite,
  });
  commandHistory.push(commandObject);

  await cmdDispatchTestFuzzerHandlerCFLite(args);
}

async function cmdDispatchTestFuzzerHandlerCFLite(args: any) {
  // Build the project
  setStatusText('Test specific fuzzer: building fuzzers in workspace');
  if (!(await buildFuzzersFromWorkspaceClusterfuzzLite())) {
    println('Build projects');
    return;
  }

  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return;
  }

  const pathOfLocal = workspaceFolder[0].uri.path;
  println('path of local: ' + pathOfLocal);

  // Run the fuzzer for 10 seconds
  println('Running fuzzer');
  setStatusText('Test specific fuzzer: running fuzzer ' + args.fuzzerName);
  await runFuzzerHandlerCFLite(
    pathOfLocal,
    args.fuzzerName,
    extensionConfig.numberOfSecondsForTestRuns.toString()
  );
  setStatusText('Test specific fuzzer: test completed of ' + args.fuzzerName);
  return;
}

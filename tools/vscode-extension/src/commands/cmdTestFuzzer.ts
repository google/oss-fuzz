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
import {runFuzzerHandler, buildFuzzersFromWorkspace} from '../ossfuzzWrappers';
import {setStatusText} from '../utils';
import {commandHistory} from '../commandUtils';
import {extensionConfig} from '../config';

/**
 * Does an end-to-end test of a project/fuzzer. This is done by
 * first building the project and then running the fuzzer.
 * @param context
 * @returns
 */

export async function cmdInputCollectorTestFuzzer() {
  setStatusText('Testing specific fuzzer: getting input');
  // Get the project name and fuzzer name to test.
  const ossFuzzProjectNameInput = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'The OSS-Fuzz project name',
  });
  if (!ossFuzzProjectNameInput) {
    println('Did not get a ossFuzzTargetProject');
    return;
  }
  println('Project name: ' + ossFuzzProjectNameInput);

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
    projectName: ossFuzzProjectNameInput.toString(),
    fuzzerName: fuzzerNameInput.toString(),
  });

  // Create a dispatcher object.
  const commandObject = new Object({
    commandType: 'oss-fuzz.TestFuzzer',
    Arguments: args,
    dispatcherFunc: cmdDispatchTestFuzzerHandler,
  });
  commandHistory.push(commandObject);

  await cmdDispatchTestFuzzerHandler(args);
}

async function cmdDispatchTestFuzzerHandler(args: any) {
  // Build the project
  setStatusText('Test specific fuzzer: building fuzzers in workspace');
  if (!(await buildFuzzersFromWorkspace(args.projectName, '', false))) {
    println('Build projects');
    return;
  }

  // Run the fuzzer for 10 seconds
  println('Running fuzzer');
  setStatusText('Test specific fuzzer: running fuzzer ' + args.fuzzerName);
  await runFuzzerHandler(
    args.projectName,
    args.fuzzerName,
    extensionConfig.numberOfSecondsForTestRuns.toString(),
    ''
  );
  setStatusText('Test specific fuzzer: test completed of ' + args.fuzzerName);
  return;
}

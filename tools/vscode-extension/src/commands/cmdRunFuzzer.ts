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
import {commandHistory} from '../commandUtils';
import {runFuzzerHandler} from '../ossfuzzWrappers';

export async function cmdInputCollectorRunSpecificFuzzer() {
  let projectNameArg = '';
  let fuzzerName = '';
  let secondsToRun = '';

  // Runs a fuzzer from a given project.
  const projectNameFromPrompt = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Type a project name',
  });
  if (!projectNameFromPrompt) {
    println('Failed to get project name');
    return;
  }
  projectNameArg = projectNameFromPrompt.toString();
  const fuzzerNameFromPrompt = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Type a fuzzer name',
  });
  if (!fuzzerNameFromPrompt) {
    println('Failed to get fuzzer name');
    return;
  }
  fuzzerName = fuzzerNameFromPrompt.toString();
  const secondsToRunInp = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Type the number of seconds to run the fuzzer',
  });
  if (!secondsToRunInp) {
    return;
  }
  secondsToRun = secondsToRunInp.toString();

  // Create an history object
  const args = new Object({
    projectName: projectNameArg,
    fuzzerName: fuzzerName,
    secondsToRun: secondsToRun,
    fuzzerCorpusPath: '',
  });

  const commandObject = new Object({
    commandType: 'oss-fuzz.RunFuzzer',
    Arguments: args,
    dispatcherFunc: cmdDispatchRunFuzzerHandler,
  });
  console.log('L1: ' + commandHistory.length);
  commandHistory.push(commandObject);

  await cmdDispatchRunFuzzerHandler(args);
  return true;
}

async function cmdDispatchRunFuzzerHandler(args: any) {
  await runFuzzerHandler(
    args.projectName,
    args.fuzzerName,
    args.secondsToRun,
    args.fuzzerCorpusPath
  );
  return;
}

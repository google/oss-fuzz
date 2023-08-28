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
import {hasOssFuzzInWorkspace, getOssFuzzWorkspaceProjectName} from '../utils';
import {buildFuzzersFromWorkspace} from '../ossfuzzWrappers';

export async function cmdInputCollectorBuildFuzzersFromWorkspace() {
  let ossFuzzProjectName = '';
  // First determine if we have a name in the workspace
  if (await hasOssFuzzInWorkspace()) {
    /**
     * The fuzzers are in the workspace, as opposed to e.g. the oss-fuzz dirctory.
     */
    ossFuzzProjectName = await getOssFuzzWorkspaceProjectName();
  } else {
    // If we did not have that, ask the user.

    const ossFuzzProjectNameInput = await vscode.window.showInputBox({
      value: '',
      placeHolder: 'The OSS-Fuzz project name',
    });
    if (!ossFuzzProjectNameInput) {
      println('Did not get a ossFuzzTargetProject');
      return false;
    }
    ossFuzzProjectName = ossFuzzProjectNameInput.toString();
  }

  // Create an history object
  const args = new Object({
    projectName: ossFuzzProjectName,
    sanitizer: '',
    toClean: false,
  });

  const commandObject = new Object({
    commandType: 'oss-fuzz.WSBuildFuzzers',
    Arguments: args,
    dispatcherFunc: cmdDispatchBuildFuzzersFromWorkspace,
  });
  console.log('L1: ' + commandHistory.length);
  commandHistory.push(commandObject);

  await cmdDispatchBuildFuzzersFromWorkspace(args);
  return true;
}

async function cmdDispatchBuildFuzzersFromWorkspace(args: any) {
  await buildFuzzersFromWorkspace(
    args.projectName,
    args.sanitizer,
    args.toClean
  );
}

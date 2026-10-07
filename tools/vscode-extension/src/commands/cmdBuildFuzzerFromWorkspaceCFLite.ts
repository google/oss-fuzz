/* eslint-disable @typescript-eslint/no-explicit-any */
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

import {commandHistory} from '../commandUtils';
import {setStatusText} from '../utils';
import {buildFuzzersFromWorkspaceClusterfuzzLite} from '../ossfuzzWrappers';

export async function cmdInputCollectorBuildFuzzersFromWorkspaceCFLite() {
  // Create an history object
  const args = new Object({
    toClean: false,
  });

  const commandObject = new Object({
    commandType: 'oss-fuzz.WSBuildFuzzers',
    Arguments: args,
    dispatcherFunc: cmdDispatchbuildFuzzersFromWorkspaceClusterfuzzLite,
  });
  console.log('L1: ' + commandHistory.length);
  commandHistory.push(commandObject);

  await cmdDispatchbuildFuzzersFromWorkspaceClusterfuzzLite(args);
  return true;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function cmdDispatchbuildFuzzersFromWorkspaceClusterfuzzLite(_args: any) {
  await setStatusText('[CFLite] Building fuzzers: starting');
  const res = await buildFuzzersFromWorkspaceClusterfuzzLite();
  if (res) {
    await setStatusText('[CFLite] Building fuzzers: finished');
  } else {
    await setStatusText('[CFLite] Building fuzzers: failed');
  }
}

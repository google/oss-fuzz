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

/**
 * Rerun the latest command
 */
export async function cmdDispatcherRe() {
  if (commandHistory.length === 0) {
    console.log('command history is empty');
    return false;
  }

  const commandObj: any = commandHistory[commandHistory.length - 1];

  console.log('Redoing');
  console.log(commandObj.commandType);
  await commandObj.dispatcherFunc(commandObj.Arguments);
  //await commandObj.dispatcherFunc(commandObj.args);
  return true;
}

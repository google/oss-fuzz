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

/**
 * Command for generating template fuzzers. This is a short-cut for rapid
 * prototyping as well as an archive for inspiration.
 */
import * as vscode from 'vscode';
import {setStatusText} from '../utils';

import {setupProjectInitialFiles} from '../projectIntegrationHelper';

export async function cmdDispatcherGenerateClusterfuzzLite(
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _context: vscode.ExtensionContext
) {
  await setStatusText('Creating OSS-Fuzz setup: starting');
  const res = await setupProjectInitialFiles(true);
  if (res) {
    await setStatusText('Creating OSS-Fuzz setup: finished');
  } else {
    await setStatusText('Creating OSS-Fuzz setup: failed');
  }
  return;
}

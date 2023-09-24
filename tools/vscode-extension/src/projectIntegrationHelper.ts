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

import path = require('path');
import {println} from './logger';

export async function setupProjectInitialFiles() {
  const wsedit = new vscode.WorkspaceEdit();
  const workspaceFolder = vscode.workspace.workspaceFolders;

  const projectGithubRepository = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Github repository for the project.',
  });
  if (!projectGithubRepository) {
    return;
  }

  const projectNameFromRepo = path.parse(projectGithubRepository).base;
  println('Derived project name: ' + projectNameFromRepo);

  const pythonFiles = await vscode.workspace.findFiles('**/*.py');
  const cppFiles = await vscode.workspace.findFiles('**/*.c++');
  const cfiles = await vscode.workspace.findFiles('**/*.c');
  const rustFiles = await vscode.workspace.findFiles('**/*.rust');
  const golangFiles = await vscode.workspace.findFiles('**/*.go');

  println('Number of python files: ' + pythonFiles.length);
  println('Number of C++ files: ' + cppFiles.length);
  println('Number of C files: ' + cfiles.length);
  println('Number of rustFiles files: ' + rustFiles.length);
  println('Number of golangFiles files: ' + golangFiles.length);

  const maxCount = Math.max(
    pythonFiles.length,
    cppFiles.length,
    cfiles.length,
    rustFiles.length,
    golangFiles.length
  );
  let target = '';
  if (maxCount === pythonFiles.length) {
    target = 'python';
  } else {
    target = 'not implemented';
  }

  println('Target language: ' + target);

  if (workspaceFolder) {
    const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

    const ossfuzzDockerFilepath = vscode.Uri.file(
      wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/Dockerfile'
    );

    vscode.window.showInformationMessage(ossfuzzDockerFilepath.toString());
    wsedit.createFile(ossfuzzDockerFilepath, {ignoreIfExists: true});

    const todaysDate = new Date();
    const currentYear = todaysDate.getFullYear();

    if (target === 'python') {
      const dockerfileTemplate = `# Copyright ${currentYear} Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
  
FROM gcr.io/oss-fuzz-base/base-builder-python
RUN python3 -m pip install --upgrade pip
RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
WORKDIR ${projectNameFromRepo}
COPY build.sh *.py $SRC/`;
      wsedit.insert(
        ossfuzzDockerFilepath,
        new vscode.Position(0, 0),
        dockerfileTemplate
      );

      const ossfuzzBuildFilepath = vscode.Uri.file(
        wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/build.sh'
      );
      vscode.window.showInformationMessage(ossfuzzBuildFilepath.toString());
      wsedit.createFile(ossfuzzBuildFilepath, {ignoreIfExists: true});
      const buildTemplate = `#!/bin/bash -eu
# Copyright ${currentYear} Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
  
python3 -m pip install .
  
# Build fuzzers (files prefixed with fuzz_) to $OUT
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done`;
      wsedit.insert(
        ossfuzzBuildFilepath,
        new vscode.Position(0, 0),
        buildTemplate
      );

      // project.yaml
      const projectYamlFilepath = vscode.Uri.file(
        wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/project.yaml'
      );
      vscode.window.showInformationMessage(projectYamlFilepath.toString());
      wsedit.createFile(projectYamlFilepath, {ignoreIfExists: true});
      const projectYamlTemplate = `homepage: "${projectGithubRepository}"
language: python
primary_contact: "<primary_contact_email>"
main_repo: "${projectGithubRepository}"
file_github_issue: true
        `;
      wsedit.insert(
        projectYamlFilepath,
        new vscode.Position(0, 0),
        projectYamlTemplate
      );

      /* Sample template fuzzer */
      const sampleFuzzFile = vscode.Uri.file(
        wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/fuzz_ex1.py'
      );
      vscode.window.showInformationMessage(projectYamlFilepath.toString());
      wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
      const sampleFuzzFileContents = `import sys
import atheris

with atheris.instrument_imports():
  # Import your target modules here to have them
  # instrumented by the fuzzer, e.g:
  # import MODULE_NAME
  pass

@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)


def main():
  # atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()`;

      wsedit.insert(
        sampleFuzzFile,
        new vscode.Position(0, 0),
        sampleFuzzFileContents
      );

      const readmeFile = vscode.Uri.file(wsPath + '/OSS-Fuzz/' + '/README.md');
      vscode.window.showInformationMessage(readmeFile.toString());
      wsedit.createFile(readmeFile, {ignoreIfExists: true});
      const readmeContents = `# OSS-Fuzz set up
  This folder is the OSS-Fuzz set up.
        `;

      wsedit.insert(readmeFile, new vscode.Position(0, 0), readmeContents);
      vscode.workspace.applyEdit(wsedit);
    }

    vscode.window.showInformationMessage('Created a new file: hello/world.md');
  }
}

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
    return false;
  }

  const projectNameFromRepo = path
    .parse(projectGithubRepository)
    .base.toLocaleLowerCase();
  println('Derived project name: ' + projectNameFromRepo);

  const pythonFiles = await vscode.workspace.findFiles('**/*.py');
  const cppFiles = await vscode.workspace.findFiles('**/*.c++');
  const cppFiles2 = await vscode.workspace.findFiles('**/*.cpp');
  const cfiles = await vscode.workspace.findFiles('**/*.c');
  const rustFiles = await vscode.workspace.findFiles('**/*.rust');
  const golangFiles = await vscode.workspace.findFiles('**/*.go');
  const javaFiles = await vscode.workspace.findFiles('**/*.java');

  println('Number of python files: ' + pythonFiles.length);
  println('Number of C++ files: ' + cppFiles.length);
  println('Number of C files: ' + cfiles.length + cppFiles2.length);
  println('Number of rustFiles files: ' + rustFiles.length);
  println('Number of golangFiles files: ' + golangFiles.length);

  const cppFilesCount = cppFiles.length + cppFiles2.length;

  const maxCount = Math.max(
    pythonFiles.length,
    cppFilesCount,
    cfiles.length,
    rustFiles.length,
    golangFiles.length,
    javaFiles.length
  );
  let target = '';
  if (maxCount === pythonFiles.length) {
    target = 'python';
  } else if (maxCount === cppFilesCount) {
    target = 'cpp';
  } else if (maxCount === cfiles.length) {
    target = 'c';
  } else if (maxCount === javaFiles.length) {
    target = 'java';
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

    if (target === 'python') {
      await setupPythonProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath
      );
    }
    if (target === 'cpp') {
      await setupCPPProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath
      );
    }
    if (target === 'c') {
      await setupCProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath
      );
    }
    if (target === 'java') {
      await setupJavaProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath
      );
    }

    vscode.window.showInformationMessage('Created a new file: hello/world.md');
  }
  return true;
}

async function setupJavaProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string
) {
  const todaysDate = new Date();
  const currentYear = todaysDate.getFullYear();

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

FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \\
    unzip maven.zip -d $SRC/maven && \\
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn
RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
WORKDIR ${projectNameFromRepo}
COPY build.sh *.java $SRC/`;
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

# Supply build instructions
# Copy all fuzzer executables to $OUT/
`;
  wsedit.insert(ossfuzzBuildFilepath, new vscode.Position(0, 0), buildTemplate);

  // project.yaml
  const projectYamlFilepath = vscode.Uri.file(
    wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/project.yaml'
  );
  vscode.window.showInformationMessage(projectYamlFilepath.toString());
  wsedit.createFile(projectYamlFilepath, {ignoreIfExists: true});
  const projectYamlTemplate = `homepage: "${projectGithubRepository}"
language: c++
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
    wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/fuzzer_example.java'
  );
  vscode.window.showInformationMessage(projectYamlFilepath.toString());
  wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
  const sampleFuzzFileContents = `// Copyright 2023 Google LLC
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
  ///////////////////////////////////////////////////////////////////////////
  import com.code_intelligence.jazzer.api.FuzzedDataProvider;

  public class OSSFuzzFUzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
      // Consume fuzzer string:
      // ... = data.consumeRemainingAsString()
    }
  }`;

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

async function setupCProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string
) {
  const todaysDate = new Date();
  const currentYear = todaysDate.getFullYear();

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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
WORKDIR ${projectNameFromRepo}
COPY build.sh *.c $SRC/`;
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

# Supply build instructions
# Use the following environment variables to build the code
# $CXX:               c++ compiler
# $CC:                c compiler
# CFLAGS:             compiler flags for C files
# CXXFLAGS:           compiler flags for CPP files
# LIB_FUZZING_ENGINE: linker flag for fuzzing harnesses

# Copy all fuzzer executables to $OUT/
`;
  wsedit.insert(ossfuzzBuildFilepath, new vscode.Position(0, 0), buildTemplate);

  // project.yaml
  const projectYamlFilepath = vscode.Uri.file(
    wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/project.yaml'
  );
  vscode.window.showInformationMessage(projectYamlFilepath.toString());
  wsedit.createFile(projectYamlFilepath, {ignoreIfExists: true});
  const projectYamlTemplate = `homepage: "${projectGithubRepository}"
language: c++
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
    wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/fuzzer_example.c'
  );
  vscode.window.showInformationMessage(projectYamlFilepath.toString());
  wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
  const sampleFuzzFileContents = `#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
        return 0;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\\0';

    // Insert fuzzer contents here
    // fuzz data in new_str

    // end of fuzzer contents

    free(new_str);
    return 0;
}`;

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

async function setupCPPProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string
) {
  const todaysDate = new Date();
  const currentYear = todaysDate.getFullYear();

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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
WORKDIR ${projectNameFromRepo}
COPY build.sh *.cpp $SRC/`;
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

# Supply build instructions
# Use the following environment variables to build the code
# $CXX:               c++ compiler
# $CC:                c compiler
# CFLAGS:             compiler flags for C files
# CXXFLAGS:           compiler flags for CPP files
# LIB_FUZZING_ENGINE: linker flag for fuzzing harnesses

# Copy all fuzzer executables to $OUT/

# Copy all fuzzer executables to $OUT/
$CXX $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer_example.cpp -o $OUT/fuzzer_example
`;
  wsedit.insert(ossfuzzBuildFilepath, new vscode.Position(0, 0), buildTemplate);

  // project.yaml
  const projectYamlFilepath = vscode.Uri.file(
    wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/project.yaml'
  );
  vscode.window.showInformationMessage(projectYamlFilepath.toString());
  wsedit.createFile(projectYamlFilepath, {ignoreIfExists: true});
  const projectYamlTemplate = `homepage: "${projectGithubRepository}"
language: c++
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
    wsPath + '/OSS-Fuzz/' + projectNameFromRepo + '/fuzzer_example.cpp'
  );
  vscode.window.showInformationMessage(projectYamlFilepath.toString());
  wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
  const sampleFuzzFileContents = `#include <fuzzer/FuzzedDataProvider.h>

#include <string>

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);


  std::string s1 = fdp.ConsumeRandomLengthString();
  if (s1.size() == 3) {
    printf("Yup yup\\n");
  }
  // Extract higher level data types used for fuzzing, e.g.
  // int ran_int = fdp.ConsumeIntegralInRange<int>(1, 1024);
  // std::string s = fdp.ConsumeRandomLengthString();

  return 0;
}`;

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

async function setupPythonProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string
) {
  const todaysDate = new Date();
  const currentYear = todaysDate.getFullYear();

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
  wsedit.insert(ossfuzzBuildFilepath, new vscode.Position(0, 0), buildTemplate);

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

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
const fs = require('fs');
import path = require('path');
import {println} from './logger';
import * as fuzzTemplate from './commands/cmdTemplate';

export async function setupProjectInitialFiles(isClusterfuzzLite: boolean) {
  const wsedit = new vscode.WorkspaceEdit();
  const workspaceFolder = vscode.workspace.workspaceFolders;
  let projectGithubRepository = '';

  const isOssFuzz = isClusterfuzzLite === false;

  // Get the repository if this is not ClusterfuzzLite
  if (isOssFuzz) {
    const tmpProjectGithubRepository = await vscode.window.showInputBox({
      value: '',
      placeHolder: 'Github repository for the project.',
    });
    if (!tmpProjectGithubRepository) {
      return false;
    }
    projectGithubRepository = tmpProjectGithubRepository;
  }

  const projectNameFromRepo = path
    .parse(projectGithubRepository)
    .base.toLocaleLowerCase();

  let pathOfLocal = '';
  if (workspaceFolder) {
    pathOfLocal = path
      .parse(workspaceFolder[0].uri.fsPath)
      .base.toLocaleLowerCase();
    println('path of local: ' + pathOfLocal);
  }
  if (isOssFuzz) {
    println('Derived project name: ' + projectNameFromRepo);
  }

  const pythonFiles = await vscode.workspace.findFiles('**/*.py');
  const cppFiles = await vscode.workspace.findFiles('**/*.c++');
  const cppFiles2 = await vscode.workspace.findFiles('**/*.cpp');
  const cppFiles3 = await vscode.workspace.findFiles('**/*.cc');
  const cfiles = await vscode.workspace.findFiles('**/*.c');
  const hfiles = await vscode.workspace.findFiles('**/*.h');
  const rustFiles = await vscode.workspace.findFiles('**/*.rust');
  const golangFiles = await vscode.workspace.findFiles('**/*.go');
  const javaFiles = await vscode.workspace.findFiles('**/*.java');

  println('Number of python files: ' + pythonFiles.length);
  println('Number of C++ files: ' + cppFiles.length + cppFiles2.length);
  println('Number of C files: ' + cfiles.length);
  println('Number of rustFiles files: ' + rustFiles.length);
  println('Number of golangFiles files: ' + golangFiles.length);
  println('Number of H files: ' + hfiles.length);

  const cppFilesCount = cppFiles.length + cppFiles2.length + cppFiles3.length;

  const maxCount = Math.max(
    pythonFiles.length,
    cppFilesCount,
    cfiles.length,
    rustFiles.length,
    golangFiles.length,
    javaFiles.length
  );
  let target = '';
  if (maxCount > 0) {
    if (maxCount === pythonFiles.length) {
      target = 'python';
    } else if (maxCount === cppFilesCount) {
      target = 'cpp';
    } else if (maxCount === cfiles.length) {
      target = 'c';
    } else if (maxCount === javaFiles.length) {
      target = 'java';
    } else {
      println('Target is not implemented');
      return true;
    }
  } else {
    if (hfiles.length > 0) {
      target = 'cpp';
    } else {
      return true;
    }
  }

  println('Target language: ' + target);

  let baseFolder = '.clusterfuzzlite';
  if (isOssFuzz) {
    baseFolder = 'OSS-Fuzz';
  }

  if (workspaceFolder) {
    const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

    // Create workflow file for ClusterFuzzLite
    if (isOssFuzz === false) {
      println('Creating the workflow file');
      const clusterfuzzWorkflowFile = vscode.Uri.file(
        wsPath + '/' + '.github' + '/' + 'workflows/cflite_pr.yml'
      );

      let tmp_target = target;
      if (tmp_target === 'cpp') {
        tmp_target = 'c++';
      }

      //println('Workflow pth: ' + clusterfuzzWorkflowFile);

      const cflite_workflow_yaml = `name: ClusterFuzzLite PR fuzzing
on:
  workflow_dispatch:
  pull_request:
    branches: [ main ]
permissions: read-all
jobs:
  PR:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        sanitizer: [address]
    steps:
    - name: Build Fuzzers (\${{ matrix.sanitizer }})
      id: build
      uses: google/clusterfuzzlite/actions/build_fuzzers@v1
      with:
        sanitizer: \${{ matrix.sanitizer }}
        language: ${tmp_target}
        bad-build-check: false
    - name: Run Fuzzers (\${{ matrix.sanitizer }})
      id: run
      uses: google/clusterfuzzlite/actions/run_fuzzers@v1
      with:
        github-token: \${{ secrets.GITHUB_TOKEN }}
        fuzz-seconds: 100
        mode: 'code-change'
        report-unreproducible-crashes: false
        sanitizer: \${{ matrix.sanitizer }}
`;

      // Create the file and add the contents
      if (fs.existsSync(clusterfuzzWorkflowFile.path) === false) {
        wsedit.createFile(clusterfuzzWorkflowFile, {ignoreIfExists: true});
        wsedit.insert(
          clusterfuzzWorkflowFile,
          new vscode.Position(0, 0),
          cflite_workflow_yaml
        );
      }
    }

    const ossfuzzDockerFilepath = vscode.Uri.file(
      wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/Dockerfile'
    );

    vscode.window.showInformationMessage(ossfuzzDockerFilepath.toString());
    //wsedit.createFile(ossfuzzDockerFilepath, {ignoreIfExists: true});

    if (target === 'python') {
      await setupPythonProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath,
        baseFolder,
        pathOfLocal,
        isOssFuzz
      );
    }
    if (target === 'cpp') {
      await setupCPPProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath,
        baseFolder,
        pathOfLocal,
        isOssFuzz
      );
    }
    if (target === 'c') {
      await setupCProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath,
        baseFolder,
        pathOfLocal,
        isOssFuzz
      );
    }
    if (target === 'java') {
      await setupJavaProjectInitialFiles(
        projectGithubRepository,
        projectNameFromRepo,
        ossfuzzDockerFilepath,
        wsedit,
        wsPath,
        baseFolder,
        isOssFuzz
      );
    }
    vscode.workspace.applyEdit(wsedit);
    vscode.window.showInformationMessage('Created a new file: hello/world.md');
  }
  return true;
}

function createProjectYamlContent(
  wsedit: vscode.WorkspaceEdit,
  wsPath: string,
  baseFolder: string,
  isOssFuzz: boolean,
  projectGithubRepository: string,
  projectNameFromRepo: string,
  language: string
) {
  const projectYamlFilepath = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/project.yaml'
  );
  if (fs.existsSync(projectYamlFilepath.path) === false) {
    vscode.window.showInformationMessage(projectYamlFilepath.toString());
    wsedit.createFile(projectYamlFilepath, {ignoreIfExists: true});
    const projectYamlTemplate = `homepage: "${projectGithubRepository}"
language: ${language}
primary_contact: "<primary_contact_email>"
main_repo: "${projectGithubRepository}"
file_github_issue: true
    `;

    const projectYamlTemplateCFLite = `language: ${language}`;

    const yamlContentToWrite = isOssFuzz
      ? projectYamlTemplate
      : projectYamlTemplateCFLite;

    wsedit.insert(
      projectYamlFilepath,
      new vscode.Position(0, 0),
      yamlContentToWrite
    );
  }
}

function getLicenseHeader() {
  const todaysDate = new Date();
  const currentYear = todaysDate.getFullYear();

  const licenseHeader = `# Copyright ${currentYear} Google LLC
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
`;

  return licenseHeader;
}

function getBaseDockerFile(language: string) {
  const languageToBasebuilder: {[id: string]: string} = {
    java: 'gcr.io/oss-fuzz-base/base-builder-jvm',
    cpp: 'gcr.io/oss-fuzz-base/base-builder',
    c: 'gcr.io/oss-fuzz-base/base-builder',
    python: 'gcr.io/oss-fuzz-base/base-builder-python',
  };
  let dockerFileContent = getLicenseHeader();
  dockerFileContent += '\n' + 'FROM ' + languageToBasebuilder[language] + '\n';

  return dockerFileContent;
}

function createReadmeFile(
  wsedit: vscode.WorkspaceEdit,
  wsPath: string,
  baseFolder: string,
  isOssFuzz: boolean
) {
  const readmeFile = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + '/README.md'
  );
  //vscode.window.showInformationMessage(readmeFile.toString());
  if (fs.existsSync(readmeFile.path) === false) {
    const readmeContents = `# OSS-Fuzz set up
This folder is the OSS-Fuzz set up.
    `;

    const readmeContentsCFLite = `# ClusterFuzzLite set up
This folder contains a fuzzing set for [ClusterFuzzLite](https://google.github.io/clusterfuzzlite).
        `;

    const readmeContentsToWrite = isOssFuzz
      ? readmeContents
      : readmeContentsCFLite;

    wsedit.createFile(readmeFile, {ignoreIfExists: true});

    wsedit.insert(readmeFile, new vscode.Position(0, 0), readmeContentsToWrite);
  }
}

async function setupJavaProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string,
  baseFolder: string,
  isOssFuzz: boolean
) {
  // Dockerfile
  const dockerfileTemplate =
    getBaseDockerFile('java') +
    ` 
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

  // build.sh
  const ossfuzzBuildFilepath = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/build.sh'
  );
  vscode.window.showInformationMessage(ossfuzzBuildFilepath.toString());
  wsedit.createFile(ossfuzzBuildFilepath, {ignoreIfExists: true});
  const buildTemplate =
    `#!/bin/bash -eu
  ` +
    getLicenseHeader() +
    `
# Supply build instructions
# Copy all fuzzer executables to $OUT/
`;
  wsedit.insert(ossfuzzBuildFilepath, new vscode.Position(0, 0), buildTemplate);

  // project.yaml
  createProjectYamlContent(
    wsedit,
    wsPath,
    baseFolder,
    isOssFuzz,
    projectGithubRepository,
    projectNameFromRepo,
    'jvm'
  );

  /* Sample template fuzzer */
  const sampleFuzzFile = vscode.Uri.file(
    wsPath +
      '/' +
      baseFolder +
      '/' +
      projectNameFromRepo +
      '/fuzzer_example.java'
  );

  wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
  const sampleFuzzFileContents = fuzzTemplate.javaLangBareTemplate;

  wsedit.insert(
    sampleFuzzFile,
    new vscode.Position(0, 0),
    sampleFuzzFileContents
  );

  createReadmeFile(wsedit, wsPath, baseFolder, isOssFuzz);
}

async function setupCProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string,
  baseFolder: string,
  baseName: string,
  isOssFuzz: boolean
) {
  // Dockerfile
  if (fs.existsSync(ossfuzzDockerFilepath.path) === false) {
    const dockerfileTemplate =
      getBaseDockerFile('cpp') +
      `
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
WORKDIR ${projectNameFromRepo}
COPY build.sh *.cpp $SRC/`;

    const dockerfileTemplateClusterfuzzLite = `FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/${baseName}
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/${baseName}`;

    const contentToWrite = isOssFuzz
      ? dockerfileTemplate
      : dockerfileTemplateClusterfuzzLite;

    // Create the file and add the contents
    wsedit.createFile(ossfuzzDockerFilepath, {ignoreIfExists: true});
    wsedit.insert(
      ossfuzzDockerFilepath,
      new vscode.Position(0, 0),
      contentToWrite
    );
  }

  // build.sh
  const ossfuzzBuildFilepath = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/build.sh'
  );
  // Only create the build file if it doesn't exist
  if (fs.existsSync(ossfuzzBuildFilepath.path) === false) {
    vscode.window.showInformationMessage(ossfuzzBuildFilepath.toString());
    wsedit.createFile(ossfuzzBuildFilepath, {ignoreIfExists: true});
    const buildTemplate =
      `#!/bin/bash -eu
  ` +
      getLicenseHeader() +
      `
# Supply build instructions
# Use the following environment variables to build the code
# $CXX:               c++ compiler
# $CC:                c compiler
# CFLAGS:             compiler flags for C files
# CXXFLAGS:           compiler flags for CPP files
# LIB_FUZZING_ENGINE: linker flag for fuzzing harnesses

# Copy all fuzzer executables to $OUT/
$CXX $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer_example.c -o $OUT/fuzzer_example
`;

    const buildTemplateClusterfuzzLite = `#!/bin/bash -eu
# Supply build instructions
# Use the following environment variables to build the code
# $CXX:               c++ compiler
# $CC:                c compiler
# CFLAGS:             compiler flags for C files
# CXXFLAGS:           compiler flags for CPP files
# LIB_FUZZING_ENGINE: linker flag for fuzzing harnesses

# Copy all fuzzer executables to $OUT/
$CC $CFLAGS $LIB_FUZZING_ENGINE \\
  $SRC/${baseName}/.clusterfuzzlite/fuzzer_example.c \\
  -o $OUT/fuzzer_example
`;

    const buildContent = isOssFuzz
      ? buildTemplate
      : buildTemplateClusterfuzzLite;
    wsedit.insert(
      ossfuzzBuildFilepath,
      new vscode.Position(0, 0),
      buildContent
    );
  }

  // project.yaml
  createProjectYamlContent(
    wsedit,
    wsPath,
    baseFolder,
    isOssFuzz,
    projectGithubRepository,
    projectNameFromRepo,
    'c'
  );

  /* Sample template fuzzer */
  const sampleFuzzFile = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/fuzzer_example.c'
  );
  if (fs.existsSync(sampleFuzzFile.path) === false) {
    wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
    const sampleFuzzFileContents = fuzzTemplate.cLangSimpleStringFuzzer;

    wsedit.insert(
      sampleFuzzFile,
      new vscode.Position(0, 0),
      sampleFuzzFileContents
    );
  }

  createReadmeFile(wsedit, wsPath, baseFolder, isOssFuzz);
}

async function setupCPPProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string,
  baseFolder: string,
  baseName: string,
  isOssFuzz: boolean
) {
  // Dockerfile
  // Only create a new Dockerfile if it doesn't already exist
  if (fs.existsSync(ossfuzzDockerFilepath.path) === false) {
    const dockerfileTemplate =
      getBaseDockerFile('cpp') +
      ` 
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
WORKDIR ${projectNameFromRepo}
COPY build.sh *.cpp $SRC/`;

    const dockerfileTemplateClusterfuzzLite = `FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/${baseName}
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/${baseName}`;

    const contentToWrite = isOssFuzz
      ? dockerfileTemplate
      : dockerfileTemplateClusterfuzzLite;

    // Create the file and add the contents
    wsedit.createFile(ossfuzzDockerFilepath, {ignoreIfExists: true});
    wsedit.insert(
      ossfuzzDockerFilepath,
      new vscode.Position(0, 0),
      contentToWrite
    );
  }

  // build.sh
  const ossfuzzBuildFilepath = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/build.sh'
  );
  // Only create the build file if it doesn't exist
  if (fs.existsSync(ossfuzzBuildFilepath.path) === false) {
    vscode.window.showInformationMessage(ossfuzzBuildFilepath.toString());
    wsedit.createFile(ossfuzzBuildFilepath, {ignoreIfExists: true});
    const buildTemplate =
      `#!/bin/bash -eu
  ` +
      getLicenseHeader() +
      `
# Supply build instructions
# Use the following environment variables to build the code
# $CXX:               c++ compiler
# $CC:                c compiler
# CFLAGS:             compiler flags for C files
# CXXFLAGS:           compiler flags for CPP files
# LIB_FUZZING_ENGINE: linker flag for fuzzing harnesses

# Copy all fuzzer executables to $OUT/
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer_example.cpp -o $OUT/fuzzer_example
`;
    const buildTemplateClusterfuzzLite = `#!/bin/bash -eu
# Supply build instructions
# Use the following environment variables to build the code
# $CXX:               c++ compiler
# $CC:                c compiler
# CFLAGS:             compiler flags for C files
# CXXFLAGS:           compiler flags for CPP files
# LIB_FUZZING_ENGINE: linker flag for fuzzing harnesses

# Copy all fuzzer executables to $OUT/
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \\
  $SRC/${baseName}/.clusterfuzzlite/fuzzer_example.cpp \\
  -o $OUT/fuzzer_example
`;

    const buildContent = isOssFuzz
      ? buildTemplate
      : buildTemplateClusterfuzzLite;
    wsedit.insert(
      ossfuzzBuildFilepath,
      new vscode.Position(0, 0),
      buildContent
    );
  }

  // project.yaml
  createProjectYamlContent(
    wsedit,
    wsPath,
    baseFolder,
    isOssFuzz,
    projectGithubRepository,
    projectNameFromRepo,
    'c++'
  );

  /* Sample template fuzzer */
  const sampleFuzzFile = vscode.Uri.file(
    wsPath +
      '/' +
      baseFolder +
      '/' +
      projectNameFromRepo +
      '/fuzzer_example.cpp'
  );
  if (fs.existsSync(sampleFuzzFile.path) === false) {
    wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
    const sampleFuzzFileContents = fuzzTemplate.cppLangFDPTemplateFuzzer;

    wsedit.insert(
      sampleFuzzFile,
      new vscode.Position(0, 0),
      sampleFuzzFileContents
    );
  }

  createReadmeFile(wsedit, wsPath, baseFolder, isOssFuzz);
}

async function setupPythonProjectInitialFiles(
  projectGithubRepository: string,
  projectNameFromRepo: string,
  ossfuzzDockerFilepath: vscode.Uri,
  wsedit: vscode.WorkspaceEdit,
  wsPath: string,
  baseFolder: string,
  baseName: string,
  isOssFuzz: boolean
) {
  // Only write to Dockerfile if it doesn't already exist
  // Dockerfile
  if (fs.existsSync(ossfuzzDockerFilepath.path) === false) {
    const dockerfileTemplate =
      getBaseDockerFile('python') +
      ` 
  RUN python3 -m pip install --upgrade pip
  RUN git clone --depth 1 ${projectGithubRepository} ${projectNameFromRepo}
  WORKDIR ${projectNameFromRepo}
  COPY build.sh *.py $SRC/`;

    const dockerfileTemplateClusterfuzzLite =
      getBaseDockerFile('python') +
      ` 
  RUN apt-get update && apt-get install -y make autoconf automake libtool

  COPY . $SRC/${baseName}
  COPY .clusterfuzzlite/build.sh $SRC/build.sh
  WORKDIR $SRC/${baseName}`;

    const contentToWrite = isOssFuzz
      ? dockerfileTemplate
      : dockerfileTemplateClusterfuzzLite;

    wsedit.insert(
      ossfuzzDockerFilepath,
      new vscode.Position(0, 0),
      contentToWrite
    );
  }

  // build.sh
  const ossfuzzBuildFilepath = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/build.sh'
  );
  // Only create the build file if it doesn't exist
  if (fs.existsSync(ossfuzzBuildFilepath.path) === false) {
    vscode.window.showInformationMessage(ossfuzzBuildFilepath.toString());
    wsedit.createFile(ossfuzzBuildFilepath, {ignoreIfExists: true});
    const buildTemplate =
      `#!/bin/bash -eu
  ` +
      getLicenseHeader() +
      `
python3 -m pip install .

# Build fuzzers (files prefixed with fuzz_) to $OUT
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done`;

    const buildTemplateClusterfuzzLite = `#!/bin/bash -eu
python3 -m pip install .

# Build fuzzers (files prefixed with fuzz_) to $OUT
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done`;

    const buildContent = isOssFuzz
      ? buildTemplate
      : buildTemplateClusterfuzzLite;
    wsedit.insert(
      ossfuzzBuildFilepath,
      new vscode.Position(0, 0),
      buildContent
    );
  }

  // project.yaml
  createProjectYamlContent(
    wsedit,
    wsPath,
    baseFolder,
    isOssFuzz,
    projectGithubRepository,
    projectNameFromRepo,
    'python'
  );

  // Sample template fuzzer
  const sampleFuzzFile = vscode.Uri.file(
    wsPath + '/' + baseFolder + '/' + projectNameFromRepo + '/fuzz_ex1.py'
  );
  if (fs.existsSync(sampleFuzzFile.path) === false) {
    wsedit.createFile(sampleFuzzFile, {ignoreIfExists: true});
    const sampleFuzzFileContents = fuzzTemplate.pythonLangFileInputFuzzer;

    wsedit.insert(
      sampleFuzzFile,
      new vscode.Position(0, 0),
      sampleFuzzFileContents
    );
  }

  // README.md
  createReadmeFile(wsedit, wsPath, baseFolder, isOssFuzz);
}

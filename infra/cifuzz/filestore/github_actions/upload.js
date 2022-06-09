#!/usr/bin/env node
// Copyright 2021 Google LLC
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
// Script for uploading an artifact. Returns 0 on success.
// Usage: upload.js <aritfactName> <rootDirectory> <file 1>...<file N>

const fs = require('fs');
const artifact = require('@actions/artifact');
const artifactClient = artifact.create()
const artifactName = process.argv[2];
const rootDirectory = process.argv[3]
const files = process.argv.slice(4);
const options = {
    continueOnError: true
}

const uploadResult = artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)
console.log(uploadResult);
if (uploadResult['failedItems']) {
  return 1;
}
return 0;

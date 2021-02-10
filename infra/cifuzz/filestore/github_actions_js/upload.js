const fs = require('fs');
const artifact = require('@actions/artifact');

if (process.argv.length < 2) {
  console.log('Must provide a file as an argument.')
  process.exit(1);
}
let jsonFilename = process.argv[process.argv.length - 1];
console.log(jsonFilename)
let fileData = fs.readFileSync(jsonFilename);
let jsonData = JSON.parse(fileData);

const artifactClient = artifact.create()
const artifactName = jsonData['artifactName'];
const files = jsonData['files'];
const rootDirectory = jsonData['rootDirectory']
const options = {
    continueOnError: true
}

const uploadResult = artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)
console.log(uploadResult);

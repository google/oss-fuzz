const fs = require('fs');

let jsonFilename = process.argv[1];
let fileData = fs.readFileSync(jsonFilename);
let jsonData = JSON.parse(fileData);

const artifact = require('@actions/artifact');
const artifactClient = artifact.create()
const artifactName = jsonData['artifactName'];
const files = jsonData['files'];
const rootDirectory = jsonData['rootDirectory']
const options = {
    continueOnError: true
}

const uploadResult = artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)
console.log(uploadResult);

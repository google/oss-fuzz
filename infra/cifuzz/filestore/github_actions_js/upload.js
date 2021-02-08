filename = process.argv[1];
const fs = require('fs');
let fileData = fs.readFileSync(filename);
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

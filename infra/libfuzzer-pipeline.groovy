// Copyright 2016 Google Inc.
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

def call(body) {
    // evaluate the body block, and collect configuration into the object
    def config = [:]
    body.resolveStrategy = Closure.DELEGATE_FIRST
    body.delegate = config
    body()

    // Mandatory configuration
    def gitUrl = config["git"]
    assert gitUrl : "git should be specified"

    // Optional configuration
    def projectName = config["name"] ?: env.JOB_BASE_NAME
    def dockerfile = config["dockerfile"] ?: "oss-fuzz/$projectName/Dockerfile"
    def sanitizers = config["sanitizers"] ?: ["address"]
    def checkoutDir = config["checkoutDir"] ?: projectName
    def dockerContextDir = config["dockerContextDir"]

    def date = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmm")
        .format(java.time.LocalDateTime.now())
    def ossFuzzUrl = 'https://github.com/google/oss-fuzz.git'

    node {
      echo "Building project $projectName"

      def wsPwd = pwd()

      for (int i = 0; i < sanitizers.size(); i++) {
        def sanitizer = sanitizers[i]
        def dockerTag = "ossfuzz/$projectName-$sanitizer"

        dir(sanitizer) {
          stage name: "Building $sanitizer sanitizer"
          def workspace = pwd();
          def out = "$wsPwd/out/$sanitizer"
          def revisions = [:]

          dir('oss-fuzz') {
              git url: ossFuzzUrl
          }

          dir(checkoutDir) {
              git url: gitUrl
              revisions[gitUrl] = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
          }

          def revText = groovy.json.JsonOutput.toJson(revisions)
          writeFile file: "$wsPwd/${sanitizer}.rev", text: revText
          echo "revisions: $revText"

          if (dockerContextDir == null) {
            dockerContextDir = new File(dockerfile)
                .getParentFile()
                .getPath();
          }

          // Build docker image
          sh "docker build -t $dockerTag -f $dockerfile $dockerContextDir"

          // Run image to produce fuzzers
          sh "rm -rf $out"
          sh "mkdir -p $out"
          sh "docker run -v $workspace/$checkoutDir:/src/$checkoutDir -v $workspace/oss-fuzz:/src/oss-fuzz -v $out:/out -e SANITIZER_FLAGS=\"-fsanitize=$sanitizer\" -t $dockerTag"

          // Copy dict and options files
          sh "cp $workspace/oss-fuzz/$projectName/*.dict $out/ || true"
          sh "cp $workspace/oss-fuzz/$projectName/*.options $out/ || true"
        }
      }

      dir ('out') {
        stage name: "Running fuzzers"
        sh "ls -alR"
        for (int i = 0; i < sanitizers.size(); i++) {
          def sanitizer = sanitizers[i]
          dir (sanitizer) {
            def d = pwd()
            def files = findFiles()
            for (int j = 0; j < files.size(); j++) {
              def file = files[j]
              if (file.name.endsWith('.dict') || file.name.endsWith('.options') || file.directory) {
                continue
              }
              echo "FILE: $file"
              sh "docker run -v $d:/out -t ossfuzz/libfuzzer-runner /out/$file -runs=1"
            }
          }
        }

        stage name: "Uploading fuzzers"
        for (int i = 0; i < sanitizers.size(); i++) {
          def sanitizer = sanitizers[i]
          dir (sanitizer) {
            def zipFile = "$projectName-$sanitizer-${date}.zip"
            def revFile = "$projectName-$sanitizer-${date}.rev"
            sh "cp $wsPwd/${sanitizer}.rev $revFile"
            sh "zip -j $zipFile *"
            sh "gsutil cp $zipFile gs://clusterfuzz-builds/$projectName/"
            sh "gsutil cp $revFile gs://clusterfuzz-builds/$projectName/"
          }
        }

        stage name: "Pushing Images"
        docker.withRegistry('', 'docker-login') {
          for (int i = 0; i < sanitizers.size(); i++) {
            def sanitizer = sanitizers[i]
            def dockerTag = "ossfuzz/$projectName-$sanitizer"
            docker.image(dockerTag).push()
          }          
        }
      }
    }

  echo 'Done'
}

return this;

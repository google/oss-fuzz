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
    def dockerfile = config["dockerfile"]
    assert dockerfile : "dockerfile should be specified"
    def gitUrl = config["git"]
    assert gitUrl : "git should be specified"

    // Optional configuration
    def projectName = config["name"] ?: env.JOB_BASE_NAME
    def sanitizers = config["sanitizers"] ?: ["address", "memory"]
    def checkoutDir = config["checkoutDir"] ?: projectName
    def needsOssFuzz = config["needsOssFuzz"] ?: false

    def date = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmm").format(java.time.LocalDateTime.now())

    node {
      echo "Building project $projectName with Dockerfile=$dockerfile"

      for (int i = 0; i < sanitizers.size(); i++) {
        def sanitizer = sanitizers[i]
        def dockerTag = "ossfuzz/$projectName-$sanitizer"

        dir(sanitizer) {
          stage name: "$sanitizer sanitizer"

          // See JENKINS-33511
          sh 'pwd > pwd.current'
          def workspace = readFile('pwd.current').trim()
          def out = "$workspace/out"

          if (needsOssFuzz) {
            dir('oss-fuzz') {
                git url: 'https://github.com/google/oss-fuzz.git'
            }

            dir(checkoutDir) {
                git url: gitUrl
            }
          } else {
            git url: gitUrl
          }

          sh "docker build -t $dockerTag -f $dockerfile ."

          sh "rm -rf $out"
          def zipFile= "$projectName-$sanitizer-${date}.zip"

          sh "mkdir -p $out"
          sh "ls -alR $workspace/"
          sh "docker run -v $workspace:/workspace -v $out:/out -e sanitizer_flags=\"-fsanitize=$sanitizer\" -t $dockerTag"
          sh "zip -j $zipFile $out/*"
          sh "gsutil cp $zipFile gs://clusterfuzz-builds/$projectName/"
        }
      }
    }

  echo 'Done'
}

return this;

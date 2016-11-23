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
    def target = new groovy.json.JsonSlurperClassic().parseText(config["target_json"])
    
    // Optional configuration
    def projectName = config["name"] ?: env.JOB_BASE_NAME
    def dockerfile = config["dockerfile"] ?: "oss-fuzz/targets/$projectName/Dockerfile"
    def sanitizers = config["sanitizers"] ?: ["address"]
    def checkoutDir = config["checkoutDir"] ?: projectName
    def dockerContextDir = config["dockerContextDir"]
    def gitUrl = config["git"]
    def svnUrl = config["svn"]

    // Flags configuration
    def sanitizerFlags = [
      "address":"-fsanitize=address",
      "undefined":"-fsanitize=bool,signed-integer-overflow,shift,vptr"
      ]

    def date = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmm")
        .format(java.time.LocalDateTime.now())

    node {
        def workspace = pwd()
        // def uid = sh(returnStdout: true, script: 'id -u $USER').trim()
        def uid = 0 // TODO: try to make $USER to work
        echo "using uid $uid"

        def srcmapFile = "$workspace/srcmap.json"
        def dockerTag = "ossfuzz/$projectName"
        echo "Building $dockerTag: $target"

        sh "rm -rf $workspace/out"
        sh "mkdir -p $workspace/out"

        stage("docker image") {
            def ossfuzzRev
            dir('oss-fuzz') {
                git url: "https://github.com/google/oss-fuzz.git"
                ossfuzzRev = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
            }

            if (gitUrl != null) {
                dir(checkoutDir) {
                    git url: gitUrl
                }
            }
            if (svnUrl != null) {
                dir(checkoutDir) {
                    svn url: svnUrl
                }
            }

            if (dockerContextDir == null) {
                dockerContextDir = new File(dockerfile)
                    .getParentFile()
                    .getPath();
            }

            sh "docker build --no-cache -t $dockerTag -f $dockerfile $dockerContextDir"
            sh "docker run --rm $dockerTag srcmap > $workspace/srcmap.json.tmp"
            // use classic slurper: http://stackoverflow.com/questions/37864542/jenkins-pipeline-notserializableexception-groovy-json-internal-lazymap
            def srcmap = new groovy.json.JsonSlurperClassic().parse(
                new File("$workspace/srcmap.json.tmp"))
            srcmap['/src'] = [ type: 'git',
                              rev: ossfuzzRev,
                              url: 'https://github.com/google/oss-fuzz.git',
                              path: "targets/$projectName" ]
            echo "srcmap: $srcmap"
            // sh "cp $workspace/srcmap.json.tmp $srcmapFile"
            writeFile file: srcmapFile, text: groovy.json.JsonOutput.toJson(srcmap)
        } // stage("docker image")

        for (int i = 0; i < sanitizers.size(); i++) {
            def sanitizer = sanitizers[i]
            dir(sanitizer) {
                def out = "$workspace/out/$sanitizer"
                def junit_reports = "$workspace/junit_reports/$sanitizer"
                sh "mkdir -p $out"
                sh "mkdir -p $junit_reports"
                stage("$sanitizer sanitizer") {
                    // Run image to produce fuzzers
                    def flags = sanitizerFlags[sanitizer]
                    sh "docker run --rm --user $uid -v $out:/out -e SANITIZER_FLAGS=\"${flags}\" -t $dockerTag compile"
                    sh "docker run --rm --user $uid -v $out:/out -v $junit_reports:/junit_reports -t ossfuzz/base-runner test_all"
                    sh "ls -al $junit_reports/"
                }
            }
        }

        stage("uploading") {
            step([$class: 'JUnitResultArchiver', testResults: 'junit_reports/**/*.xml'])
            dir('out') {
                for (int i = 0; i < sanitizers.size(); i++) {
                    def sanitizer = sanitizers[i]
                    dir (sanitizer) {
                        def zipFile = "$projectName-$sanitizer-${date}.zip"
                        sh "zip -j $zipFile *"
                        sh "gsutil cp $zipFile gs://clusterfuzz-builds/$projectName/"
                        def stampedSrcmap = "$projectName-$sanitizer-${date}.srcmap.json"
                        sh "cp $srcmapFile $stampedSrcmap"
                        sh "gsutil cp $stampedSrcmap gs://clusterfuzz-builds/$projectName/"
                    }
                }
            }
        } // stage("uploading")

        stage("pushing image") {
            docker.withRegistry('', 'docker-login') {
                docker.image(dockerTag).push()
            }
        } // stage("pushing image")
    } // node
}  // call

return this;

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

// Jenkins build script for base images.
node {
  git url: 'https://github.com/google/oss-fuzz/'
  
  stage("infra/base-images/all.sh") {
    sh "infra/base-images/all.sh --no-cache"
  }
  
  stage("docker push") {
    def images = ['ossfuzz/base-image', 'ossfuzz/base-clang', 'ossfuzz/base-libfuzzer',
                  'ossfuzz/base-runner', 'ossfuzz/base-runner-debug',
                  'ossfuzz/base-builder',]  
    
    docker.withRegistry('', 'docker-login') {
        for (int i = 0; i < images.size(); i++) {
            def image = images[i]
            docker.image(image).push()
        }
    }
  }
}

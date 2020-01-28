# Copyright 2020 Google LLC
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
"""This module contains a list of test repository's used in unit/integration
tests.

Note: If you notice tests failing for unexpected reasons, make sure the data
in the test repos are correct. This is because the test repos are dynamic and
may change.

Note: This should be removed when a better method of testing is established.
"""

import collections

ExampleRepo = collections.namedtuple('ExampleRepo',
                                     ['project_name', 'oss_repo_name', 'git_repo_name', 'git_url', 'commit_sha'])

# WARNING: These tests  are dependent upon the following repos existing and
# the specified commits existing.
TEST_REPOS = [
    ExampleRepo(project_name='curl', oss_repo_name='curl', git_repo_name='curl',
                git_url='https://github.com/curl/curl.git',
                commit_sha='bc5d22c3dede2f04870c37aec9a50474c4b888ad'),
    ExampleRepo(project_name='usrsctp', oss_repo_name='usrsctp',git_repo_name='usrsctp',
                git_url='https://github.com/weinrank/usrsctp',
                commit_sha='4886aaa49fb90e479226fcfc3241d74208908232'),
    ExampleRepo(project_name='ndpi', oss_repo_name='ndpi',git_repo_name='nDPI',
                git_url='https://github.com/ntop/nDPI.git',
                commit_sha='c4d476cc583a2ef1e9814134efa4fbf484564ed7'),
    ExampleRepo(project_name='libarchive', oss_repo_name='libarchive', git_repo_name='libarchive',
                git_url='https://github.com/libarchive/libarchive.git',
                commit_sha='458e49358f17ec58d65ab1c45cf299baaf3c98d1')
]

INVALID_REPO = ExampleRepo(project_name='notaproj', oss_repo_name='notarepo', git_repo_name='notarepo',
            git_url='invalid.git',
            commit_sha='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

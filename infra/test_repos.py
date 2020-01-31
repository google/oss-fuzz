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
import os

ExampleRepo = collections.namedtuple('ExampleRepo', [
    'project_name', 'oss_repo_name', 'git_repo_name', 'git_url', 'new_commit',
    'old_commit', 'intro_commit', 'fuzz_target', 'test_case_path'
])

TEST_DIR_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'testcases')

# WARNING: These tests  are dependent upon the following repos existing and
# the specified commits existing.
TEST_REPOS = [
    ExampleRepo(project_name='usrsctp',
                oss_repo_name='usrsctp',
                git_repo_name='usrsctp',
                git_url='https://github.com/weinrank/usrsctp',
                old_commit='4886aaa49fb90e479226fcfc3241d74208908232',
                new_commit='c710749b1053978179a027973a3ea3bccf20ee5c',
                intro_commit='457d6ead58e82584d9dcb826f6739347f59ebd3a',
                fuzz_target='fuzzer_connect',
                test_case_path=os.path.join(TEST_DIR_PATH,
                                            'usrsctp_test_data')),
    ExampleRepo(project_name='curl',
                oss_repo_name='curl',
                git_repo_name='curl',
                git_url='https://github.com/curl/curl.git',
                old_commit='df26f5f9c36e19cd503c0e462e9f72ad37b84c82',
                new_commit='dda418266c99ceab368d723facb52069cbb9c8d5',
                intro_commit='df26f5f9c36e19cd503c0e462e9f72ad37b84c82',
                fuzz_target='curl_fuzzer_ftp',
                test_case_path=os.path.join(TEST_DIR_PATH, 'curl_test_data')),
    ExampleRepo(project_name='libarchive',
                oss_repo_name='libarchive',
                git_repo_name='libarchive',
                git_url='https://github.com/libarchive/libarchive.git',
                old_commit='5bd2a9b6658a3a6efa20bb9ad75bd39a44d71da6',
                new_commit='458e49358f17ec58d65ab1c45cf299baaf3c98d1',
                intro_commit='840266712006de5e737f8052db920dfea2be4260',
                fuzz_target='libarchive_fuzzer',
                test_case_path=os.path.join(TEST_DIR_PATH,
                                            'libarchive_test_data'))
]

INVALID_REPO = ExampleRepo(project_name='notaproj',
                           oss_repo_name='notarepo',
                           git_repo_name='notarepo',
                           git_url='invalid.git',
                           old_commit='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                           new_commit='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                           intro_commit='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                           fuzz_target='NONEFUZZER',
                           test_case_path='not/a/path')

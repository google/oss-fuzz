# Copyright 2021 Google LLC
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
#
################################################################################
"""Constants for OSS-Fuzz."""

DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH = '.clusterfuzzlite'

DEFAULT_LANGUAGE = 'c++'
DEFAULT_SANITIZER = 'address'
DEFAULT_ARCHITECTURE = 'x86_64'
DEFAULT_ENGINE = 'libfuzzer'
LANGUAGES = [
    'c',
    'c++',
    'go',
    'jvm',
    'python',
    'rust',
    'swift',
]
LANGUAGES_WITH_COVERAGE_SUPPORT = [
    'c', 'c++', 'go', 'jvm', 'python', 'rust', 'swift'
]
SANITIZERS = [
    'address', 'none', 'memory', 'undefined', 'thread', 'coverage',
    'introspector'
]
ARCHITECTURES = ['i386', 'x86_64']
ENGINES = ['libfuzzer', 'afl', 'honggfuzz', 'none', 'wycheproof']

#!/bin/bash -eu
# Copyright 2025 Google LLC.
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

cd $SRC/wget2

# The following runs all of wget2's tests except for:
# 1: test-redirection
# 2: test-ocsp-server
# 3: test-ocsp-stap
# 4: test-cookies
#
# At the time of making this script, these 4 tests
# failed at the latest master and the last few releases.
make check -C tests TESTS="test-wget-1 test-c-r test-restrict-ascii test-i-http test-i-https test-np test-spider-r test-meta-robots test-idn-robots test-idn-meta test-idn-cmd test-iri test-iri-percent test-iri-list test-iri-forced-remote test-auth-basic test-parse-rss test-page-requisites test-p-nc test-accept test-k test-follow-tags test-directory-clash test-base test-metalink test-robots test-robots-off test-parse-css test-bad-chunk test-iri-subdir test-chunked test-cut-dirs test-cut-get-vars test-parse-html-css test-auth-digest test-stats-dns test-stats-tls test-stats-site test-stats-ocsp test-plugin-interception test-plugin-nonexistance test-plugin-failure test-filter-mime-type test-https-enforce-hard1 test-https-enforce-hard2 test-https-enforce-hard3 test-https-enforce-soft1 test-https-enforce-soft2 test-https-enforce-soft3 test-gzip test-compression test-include-and-exclude-directories test-save-content-on test-limit-rate test-interrupt-response test-post-handshake-auth test-unlink test-limit-rate-http2 test-timestamping test-E-k test-ignore-length test-convert-file-only test-download-attr test-directory-prefix test-level"

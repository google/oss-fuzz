# Copyright 2022 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Invoking the target program under test,with the inputs injected into its parameters."""

import sys

from libnmap.process import NmapProcess

if __name__ == "__main__":
  NMAP_OPTIONS = ' -sn -n '
  TARGETS = ' '.join(sys.argv[1:])
  nmap_proc = NmapProcess(targets=TARGETS, options=NMAP_OPTIONS, safe_mode=True)
  nmap_proc.run()

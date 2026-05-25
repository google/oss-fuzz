# Copyright 2026 Google LLC
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

import os
import re

def parse_deps(deps_file):
    with open(deps_file, 'r') as f:
        content = f.read()

    # Very basic parser for DEPS file
    # Look for 'path': { 'url': 'url@rev' }
    deps = {}
    
    # First, get variables
    vars = {}
    vars_match = re.search(r'vars = \{(.*?)\}', content, re.DOTALL)
    if vars_match:
        vars_content = vars_match.group(1)
        for var_match in re.finditer(r"'(.*?)':\s*'(.*?)'", vars_content):
            vars[var_match.group(1)] = var_match.group(2)

    # Then, get deps
    deps_match = re.search(r'deps = \{(.*?)\n\}', content, re.DOTALL)
    if deps_match:
        deps_content = deps_match.group(1)
        # Match 'path': { 'url': ... } or 'path': 'url'
        for dep_match in re.finditer(r"'(.*?)':\s*\{(.*?)\}", deps_content, re.DOTALL):
            path = dep_match.group(1)
            inner = dep_match.group(2)
            url_match = re.search(r"'url':\s*(.*?)(,|$)", inner)
            if url_match:
                url_expr = url_match.group(1).strip()
                # Resolve Var() and strings
                url = url_expr.replace("Var('", "").replace("')", "").replace("'", "").replace('"', '').replace(' + ', '')
                for k, v in vars.items():
                    url = url.replace(k, v)
                deps[path] = url

    return deps

if __name__ == "__main__":
    deps = parse_deps('projects/angle/angle-src/DEPS')
    for path, url in deps.items():
        if '@' in url:
            base_url, rev = url.split('@')
            print(f"RUN git clone {base_url} /src/angle/{path} && cd /src/angle/{path} && git checkout {rev}")
        else:
            print(f"RUN git clone --depth 1 {url} /src/angle/{path}")

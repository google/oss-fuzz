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

import re
import glob
import sys

def translate_proto(filepath):
  with open(filepath, 'r') as f:
    content = f.read()

  # Replace edition with syntax = "proto2";
  content = re.sub(r'edition\s*=\s*"2023"\s*;', 'syntax = "proto2";', content)

  # Remove file-level features
  content = re.sub(r'option\s+features\.[a-zA-Z_.]+\s*=\s*[a-zA-Z_]+\s*;', '', content)

  # Extract all oneof blocks and replace them with placeholders
  oneofs = []
  def replace_oneof(match):
    oneofs.append(match.group(0))
    return f"__ONEOF_PLACEHOLDER_{len(oneofs) - 1}__"

  # Match oneof block: oneof name { ... }
  content = re.sub(r'(?s)\boneof\s+[a-zA-Z0-9_]+\s*\{[^}]*\}', replace_oneof, content)

  # Prepend 'optional ' to all singular fields in the rest of the file.
  # This regex matches across multiple lines ([^;]*) until the semicolon.
  pattern = r'(?m)^(\s*)(?!(optional|repeated|required|map|oneof|message|enum|import|package|option|syntax|extensions|reserved|edition)[\s\n])([a-zA-Z0-9_.]+)\s+([a-zA-Z0-9_.]+)\s*=\s*(\d+)([^;]*);'
  content = re.sub(pattern, r'\1optional \3 \4 = \5\6;', content)

  # Restore oneof blocks
  for i, oneof_block in enumerate(oneofs):
    placeholder = f"__ONEOF_PLACEHOLDER_{i}__"
    content = content.replace(placeholder, oneof_block)

  # Clean up the features.field_presence option from all fields (including inside oneofs)
  content = re.sub(r'\s*\[\s*features\.field_presence\s*=\s*EXPLICIT\s*\]', '', content)
  content = re.sub(r',\s*features\.field_presence\s*=\s*EXPLICIT', '', content)
  content = re.sub(r'features\.field_presence\s*=\s*EXPLICIT\s*,\s*', '', content)
  content = re.sub(r'(?s)features\s*\{\s*field_presence\s*:\s*[A-Z]+\s*\}', '', content)

  with open(filepath, 'w') as f:
    f.write(content)

def main():
  for proto_file in glob.glob('proto/*.proto'):
    print(f"Translating {proto_file}...")
    translate_proto(proto_file)

if __name__ == '__main__':
  main()

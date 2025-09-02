#!/usr/bin/env bash
# Copyright 2025 Google LLC
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

set -euo pipefail

# Seed corpora generator for gemini-cli OSS-Fuzz integration
# This script creates and populates all corpus directories with appropriate seed data

BASE="${1:-./oss-fuzz/gemini_cli/corpus}"

echo "Creating seed corpora in: $BASE"

# Create all corpus directories
mkdir -p \
  "$BASE/FuzzMCPDecoder" \
  "$BASE/FuzzSlashCommands" \
  "$BASE/FuzzShellValidation" \
  "$BASE/FuzzSymlinkValidation" \
  "$BASE/FuzzPathValidation" \
  "$BASE/FuzzFileSystemOperations" \
  "$BASE/FuzzCryptoOperations" \
  "$BASE/FuzzContextFileParser" \
  "$BASE/FuzzURLOmega" \
  "$BASE/FuzzTemplateOmega" \
  "$BASE/FuzzZipReaderOmega" \
  "$BASE/FuzzRegexOmega" \
  "$BASE/FuzzCSVOmega" \
  "$BASE/FuzzJSONDecoderOmega" \
  "$BASE/FuzzBase64Omega" \
  "$BASE/FuzzTimeParsingOmega" \
  "$BASE/FuzzHTTPHeaderOmega" \
  "$BASE/FuzzINIOmega" \
  "$BASE/FuzzEnvExpandOmega"

echo "Created corpus directories"

# FuzzMCPDecoder - JSON-RPC messages
printf '%s\n' '{"jsonrpc":"2.0","method":"ping","params":{}}' > "$BASE/FuzzMCPDecoder/simple.json"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"sum","params":{"nums":[1,2,3],"meta":{"ok":true}}}' > "$BASE/FuzzMCPDecoder/nested.json"
printf '%s\n' '{"jsonrpc":"2.0","id":"abc","method":"notify","params":{"message":"hello"}}' > "$BASE/FuzzMCPDecoder/notification.json"
printf '%s\n' '{"jsonrpc":"2.0","id":42,"error":{"code":-32700,"message":"Parse error"}}' > "$BASE/FuzzMCPDecoder/error.json"

# FuzzSlashCommands - CLI slash commands
printf '/status\n' > "$BASE/FuzzSlashCommands/basic.txt"
printf '/deploy -env=prod --force\n' > "$BASE/FuzzSlashCommands/params.txt"
printf '/build ../../etc/passwd\n' > "$BASE/FuzzSlashCommands/traversal.txt"
printf '/config set key=value\n' > "$BASE/FuzzSlashCommands/set.txt"
printf '/help --verbose\n' > "$BASE/FuzzSlashCommands/help.txt"

# FuzzShellValidation - Shell command validation
printf 'echo hello\n' > "$BASE/FuzzShellValidation/echo.txt"
printf 'env | head -n 1\n' > "$BASE/FuzzShellValidation/pipe.txt"
printf 'echo $HOME\n' > "$BASE/FuzzShellValidation/vars.txt"
printf 'ls -la /tmp\n' > "$BASE/FuzzShellValidation/ls.txt"
printf 'cat file.txt 2>/dev/null\n' > "$BASE/FuzzShellValidation/cat.txt"

# FuzzSymlinkValidation - Symlink path validation
printf './link\n' > "$BASE/FuzzSymlinkValidation/rel.txt"
printf '../../etc/passwd\n' > "$BASE/FuzzSymlinkValidation/traversal.txt"
printf 'C:\\Windows\\System32\\drivers\n' > "$BASE/FuzzSymlinkValidation/win.txt"
printf '/usr/local/bin/app\n' > "$BASE/FuzzSymlinkValidation/abs.txt"
printf '../parent/file\n' > "$BASE/FuzzSymlinkValidation/dots.txt"

# FuzzPathValidation - File path validation
printf '/var/log/app.log\n' > "$BASE/FuzzPathValidation/absolute.txt"
printf 'a/b/../c\n' > "$BASE/FuzzPathValidation/relative.txt"
printf '../tmp\n' > "$BASE/FuzzPathValidation/dots.txt"
printf './config.json\n' > "$BASE/FuzzPathValidation/dot.txt"
printf 'data/input.txt\n' > "$BASE/FuzzPathValidation/simple.txt"

# FuzzFileSystemOperations - File system operation names
printf 'alpha-1\ndata_file\ntmp123\n' > "$BASE/FuzzFileSystemOperations/names.txt"
printf 'file.with.dots.txt\n' > "$BASE/FuzzFileSystemOperations/dots.txt"
printf 'file-with-dashes.txt\n' > "$BASE/FuzzFileSystemOperations/dashes.txt"
printf 'file_with_underscores.txt\n' > "$BASE/FuzzFileSystemOperations/underscores.txt"

# FuzzCryptoOperations - Cryptographic data
printf 'keymessage' > "$BASE/FuzzCryptoOperations/even-split-1.bin"
printf 'AABBCCDD' > "$BASE/FuzzCryptoOperations/even-split-2.bin"
printf 'secretkey123' > "$BASE/FuzzCryptoOperations/key.txt"
printf 'data-to-encrypt' > "$BASE/FuzzCryptoOperations/data.txt"

# FuzzContextFileParser - Configuration file parsing
printf 'PORT=8080\nDEBUG=false\nNAME=gemini\n' > "$BASE/FuzzContextFileParser/config.env"
printf '%s\n' '{"feature":"x","enabled":true,"limits":{"n":5}}' > "$BASE/FuzzContextFileParser/json.json"
printf 'key1=value1\nkey2=value2\n' > "$BASE/FuzzContextFileParser/simple.txt"
printf '# Comment\nSETTING=true\n' > "$BASE/FuzzContextFileParser/commented.txt"

# FuzzURLOmega - URL parsing
printf 'https://example.com/path?a=1&b=two\n' > "$BASE/FuzzURLOmega/basic.txt"
printf 'https://example.com/%7Euser?q=%5B1%2C2%5D\n' > "$BASE/FuzzURLOmega/encoded.txt"
printf 'http://localhost:8080/api/v1\n' > "$BASE/FuzzURLOmega/localhost.txt"
printf 'ftp://ftp.example.com/file.txt\n' > "$BASE/FuzzURLOmega/ftp.txt"

# FuzzTemplateOmega - Template parsing
printf '{{.}}\n' > "$BASE/FuzzTemplateOmega/minimal.tmpl"
printf '{{if .}}ok{{end}}\n' > "$BASE/FuzzTemplateOmega/if.tmpl"
printf '{{range .}}{{.}}{{end}}\n' > "$BASE/FuzzTemplateOmega/range.tmpl"
printf '{{.Name}}: {{.Value}}\n' > "$BASE/FuzzTemplateOmega/struct.tmpl"
printf '{{define "T"}}{{.}}{{end}}\n' > "$BASE/FuzzTemplateOmega/define.tmpl"

# FuzzZipReaderOmega - ZIP file parsing
if command -v zip >/dev/null 2>&1; then
  tmpd="$(mktemp -d)"
  echo "hello zip content" > "$tmpd/README.txt"
  mkdir -p "$tmpd/subdir"
  echo "nested file" > "$tmpd/subdir/nested.txt"
  (cd "$tmpd" && zip -q "$BASE/FuzzZipReaderOmega/hello.zip" README.txt subdir/nested.txt)
  rm -rf "$tmpd"
  echo "Created hello.zip with sample content"
else
  printf 'Put a tiny zip here (e.g., zip -q hello.zip README.txt)\n' > "$BASE/FuzzZipReaderOmega/README.txt"
  echo "zip command not found, created placeholder"
fi

# FuzzRegexOmega - Regular expression patterns
printf '^[a-z0-9_-]{1,16}$\n' > "$BASE/FuzzRegexOmega/simple.txt"
printf '^[\w.-]+@[\w.-]+\.[A-Za-z]{2,}$\n' > "$BASE/FuzzRegexOmega/emailish.txt"
printf '^(?=.{1,10}$)[a-z]+$\n' > "$BASE/FuzzRegexOmega/lookahead.txt"
printf '\d{3}-\d{2}-\d{4}\n' > "$BASE/FuzzRegexOmega/ssn.txt"
printf '(https?://[^\s]+)\n' > "$BASE/FuzzRegexOmega/url.txt"

# FuzzCSVOmega - CSV parsing
printf 'a,b,c\n1,2,3\n' > "$BASE/FuzzCSVOmega/basic.csv"
printf '"id","name","note"\n"1","alice","hi"\n' > "$BASE/FuzzCSVOmega/quotes.csv"
printf 'name,age,city\nJohn,25,NYC\nJane,30,LA\n' > "$BASE/FuzzCSVOmega/people.csv"
printf 'field1,field2\nval1,val2\n' > "$BASE/FuzzCSVOmega/simple.csv"

# FuzzJSONDecoderOmega - JSON parsing with dictionary and options
printf '{"a":1,"b":[true,false,null]}\n' > "$BASE/FuzzJSONDecoderOmega/obj.json"
printf '[1,2,{"k":"v"}]\n' > "$BASE/FuzzJSONDecoderOmega/arr.json"
printf '{"nested":{"deep":{"value":42}}}\n' > "$BASE/FuzzJSONDecoderOmega/nested.json"
printf '["string",123,true,false,null]\n' > "$BASE/FuzzJSONDecoderOmega/mixed.json"

# Create dictionary file for JSON fuzzer
cat > "$BASE/FuzzJSONDecoderOmega/JSON.dict" <<'EOF'
"true"
"false"
"null"
"{"
"}"
"["
"]"
":"
","
"\""
EOF

# Create options file for JSON fuzzer
cat > "$BASE/FuzzJSONDecoderOmega/FuzzJSONDecoderOmega.options" <<'EOF'
[max_len=8192]
[dict=JSON.dict]
EOF

# FuzzBase64Omega - Base64 encoding
printf 'SGVsbG8=\n' > "$BASE/FuzzBase64Omega/std.txt"
printf 'SGVsbG8\n' > "$BASE/FuzzBase64Omega/url.txt"
printf 'dGVzdA==\n' > "$BASE/FuzzBase64Omega/test.txt"
printf 'Zm9vYmFy\n' > "$BASE/FuzzBase64Omega/foobar.txt"

# FuzzTimeParsingOmega - Time and date parsing
printf '2025-01-01T12:34:56Z\n' > "$BASE/FuzzTimeParsingOmega/iso.txt"
printf '2024-12-31\n' > "$BASE/FuzzTimeParsingOmega/date.txt"
printf '1735738496\n' > "$BASE/FuzzTimeParsingOmega/unix.txt"
printf '2025-01-01 12:34:56\n' > "$BASE/FuzzTimeParsingOmega/datetime.txt"
printf 'Mon, 01 Jan 2025 12:34:56 GMT\n' > "$BASE/FuzzTimeParsingOmega/rfc.txt"

# FuzzHTTPHeaderOmega - HTTP header parsing
printf 'Content-Type: application/json\nX-Id: 1\n' > "$BASE/FuzzHTTPHeaderOmega/basic.txt"
printf 'X-A: a\nX-B: b\n' > "$BASE/FuzzHTTPHeaderOmega/multi.txt"
printf 'Authorization: Bearer token123\n' > "$BASE/FuzzHTTPHeaderOmega/auth.txt"
printf 'Content-Length: 123\n' > "$BASE/FuzzHTTPHeaderOmega/length.txt"

# FuzzINIOmega - INI file parsing
printf '[core]\nenabled=true\nname=gemini\n' > "$BASE/FuzzINIOmega/basic.ini"
printf '[section1]\nkey1=val1\n[section2]\nkey2=val2\n' > "$BASE/FuzzINIOmega/multi.ini"
printf '; Comment\n[app]\ndebug=true\nport=8080\n' > "$BASE/FuzzINIOmega/commented.ini"

# FuzzEnvExpandOmega - Environment variable expansion
printf 'PATH=$PATH\nHOME=${HOME}\nX=$X$Y\n' > "$BASE/FuzzEnvExpandOmega/vars.txt"
printf '${USER:-default}\n' > "$BASE/FuzzEnvExpandOmega/default.txt"
printf '$PWD/files\n' > "$BASE/FuzzEnvExpandOmega/pwd.txt"

echo "Seed corpora created successfully in: $BASE"

# Summary
echo ""
echo "=== CORPUS SUMMARY ==="
echo "Total directories created: $(find "$BASE" -maxdepth 1 -type d | wc -l)"
echo "Total files created: $(find "$BASE" -type f | wc -l)"
echo ""
echo "Empty directories (if any):"
for d in "$BASE"/*; do
  if [ -d "$d" ] && [ -z "$(find "$d" -maxdepth 1 -type f -print -quit)" ]; then
    echo "  $(basename "$d")"
  fi
done

echo ""
echo "Files created:"
find "$BASE" -type f | sort

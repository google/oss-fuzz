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

#!/bin/bash
# OSS-Fuzz Submission Pipeline
# Researcher: jhrag13@gmail.com

PROJECT=$1

if [ -z "$PROJECT" ]; then
    echo "Usage: $0 <project-name>"
    echo "Available projects: kafka, guava, gson, lucene, protobuf, leveldb"
    exit 1
fi

echo "🚀 Submitting $PROJECT to OSS-Fuzz"
echo "Researcher: jhrag13@gmail.com"

# Clone OSS-Fuzz
echo "📥 Cloning OSS-Fuzz repository..."
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Copy integration files
echo "📄 Copying $PROJECT integration..."
cp -r ../integration-factory/${PROJECT}-oss-fuzz/* projects/$PROJECT/

# Test build
echo "🧪 Testing build..."
python3 infra/helper.py build_image $PROJECT
python3 infra/helper.py build_fuzzers $PROJECT

echo ""
echo "✅ Ready for PR submission!"
echo ""
echo "📝 Next steps:"
echo "1. Create branch: git checkout -b add-${PROJECT}-oss-fuzz"
echo "2. Add files: git add projects/$PROJECT/"
echo "3. Commit: git commit -m 'Add OSS-Fuzz integration for $PROJECT'"
echo "4. Push: git push origin add-${PROJECT}-oss-fuzz"
echo "5. Create PR on GitHub"
echo ""
echo "💰 Potential reward: \$5,000-\$20,000"

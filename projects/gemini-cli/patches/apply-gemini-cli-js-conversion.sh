#!/bin/bash
# Apply Gemini CLI JavaScript conversion patch
# Usage: ./apply-gemini-cli-js-conversion.sh

set -e

echo "🔧 Applying Gemini CLI JavaScript conversion patch..."

# Check if we're in the right directory
if [ ! -f "infra/helper.py" ]; then
    echo "❌ Error: This script must be run from the oss-fuzz repository root"
    echo "   Current directory: $(pwd)"
    echo "   Expected: oss-fuzz repository with infra/helper.py"
    exit 1
fi

# Apply the patch
echo "📋 Applying patch..."
git apply gemini-cli-js-conversion-complete.patch

# Make build.sh executable
echo "🔧 Making build.sh executable..."
chmod +x projects/gemini-cli/build.sh

# Stage all changes
echo "📦 Staging changes..."
git add projects/gemini-cli/

# Commit the changes
echo "💾 Committing changes..."
git commit -m "feat(oss-fuzz): convert gemini-cli fuzzers to JavaScript with Apache 2.0 licensing

- Convert from Go to JavaScript fuzzing to match upstream TypeScript codebase
- Add 6 JavaScript fuzzers targeting actual production code
- Update project.yaml, Dockerfile, and build.sh for JavaScript infrastructure
- Include Apache 2.0 license headers on all files
- Add upstream module locator for dynamic import resolution
- Maintain comprehensive security validation and error handling"

echo "✅ Successfully applied Gemini CLI JavaScript conversion!"
echo ""
echo "📋 Next steps:"
echo "1. Test the build: python3 infra/helper.py build_fuzzers gemini-cli"
echo "2. Push to your PR: git push origin <your-branch>"
echo "3. Verify in OSS-Fuzz CI"
echo ""
echo "🔍 If you see UPSTREAM_*_NOT_FOUND errors, update the paths in:"
echo "   projects/gemini-cli/fuzzers/_upstream_locator.mjs"

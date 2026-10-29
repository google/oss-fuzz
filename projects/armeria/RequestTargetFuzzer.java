// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.linecorp.armeria.common.RequestTarget;
import com.linecorp.armeria.internal.common.DefaultRequestTarget;

public class RequestTargetFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final boolean allowSemicolon = data.consumeBoolean();
        final boolean allowDoubleDotsInQuery = data.consumeBoolean();
        final String input = data.consumeRemainingAsString();

        final RequestTarget server = DefaultRequestTarget.forServer(input, allowSemicolon, allowDoubleDotsInQuery);
        if (server != null) {
            final String path = server.path();
            // Normalized paths must not allow traversal (CVE-2021-43795).
            if (path.contains("/../") || path.endsWith("/..")) {
                throw new IllegalStateException("Path traversal in normalized path: " + path);
            }
        }

        RequestTarget.forClient(input);
    }
}

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

import com.linecorp.armeria.common.QueryParams;

public class QueryParamsFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final int maxParams = data.consumeInt(1, 1024);
        final boolean semicolonAsSeparator = data.consumeBoolean();
        // Query strings on the wire are ASCII; arbitrary UTF-16 (e.g. lone surrogates) can't round trip.
        final String input = data.consumeRemainingAsAsciiString();

        final QueryParams params = QueryParams.fromQueryString(input, maxParams, semicolonAsSeparator);
        final QueryParams reparsed = QueryParams.fromQueryString(params.toQueryString(), maxParams, false);
        if (!params.equals(reparsed)) {
            throw new IllegalStateException("Round trip mismatch: " + params + " != " + reparsed);
        }
    }
}

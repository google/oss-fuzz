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

import com.linecorp.armeria.common.Cookie;
import com.linecorp.armeria.common.Cookies;

public class CookieFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final boolean strict = data.consumeBoolean();
        final String input = data.consumeRemainingAsString();

        final Cookies cookies = Cookie.fromCookieHeader(strict, input);
        if (!cookies.isEmpty()) {
            Cookie.toCookieHeader(false, cookies);
        }

        final Cookie cookie = Cookie.fromSetCookieHeader(strict, input);
        if (cookie != null) {
            cookie.toSetCookieHeader(false);
        }
    }
}

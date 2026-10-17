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
////////////////////////////////////////////////////////////////////////////////

package fuzz.axis2.common;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.nio.charset.StandardCharsets;

/**
 * The few bug oracles the request-pipeline fuzzers use, besides Jazzer's own detectors
 * (uncaught exceptions, timeouts, OOM, and the built-in sanitizers).
 *
 *  - canary strings that must never reach an anonymous caller (see Env.*_CANARY)
 *  - StackOverflowError / OutOfMemoryError that Axis2 caught and only logged (see WatchLog);
 *    AxisServlet and the engine catch Throwable, which would otherwise hide them from Jazzer
 *
 * Jazzer de-duplicates crashes by stack trace, and every finding of one oracle would be thrown
 * from the same place, so each finding gets a synthetic top frame named after its key.
 */
public final class Findings {

    private static volatile String swallowed;
    private static volatile Throwable swallowedSite;

    private Findings() {
    }

    /** Called by Deliver before a request is processed. */
    static void begin() {
        swallowed = null;
        swallowedSite = null;
    }

    /** Called by WatchLog for every Throwable Axis2 logs. */
    static void logged(Throwable t) {
        if (swallowed != null) {
            return;
        }
        int depth = 0;
        for (Throwable c = t; c != null && depth < 32; c = c.getCause(), depth++) {
            if (c instanceof StackOverflowError || c instanceof OutOfMemoryError) {
                swallowed = c.getClass().getSimpleName() + " caught and logged by Axis2 while handling a request";
                swallowedSite = c;
                return;
            }
        }
    }

    /** Called by Deliver after a request: turns a swallowed StackOverflowError/OOM into a finding. */
    static void end() {
        String what = swallowed;
        if (what != null) {
            Throwable site = swallowedSite;
            begin();
            throw with(new FuzzerSecurityIssueLow(what, site), "swallowed_" + site.getClass().getSimpleName(), site);
        }
    }

    /** Hard finding if any canary is in the response but was not in the request. */
    public static void canaries(String responseBody, byte[] requestBytes, String... canaries) {
        String reqText = new String(requestBytes, StandardCharsets.ISO_8859_1);
        for (String c : canaries) {
            if (responseBody.contains(c) && !reqText.contains(c)) {
                throw with(new FuzzerSecurityIssueHigh("Canary '" + c + "' served to an anonymous caller"),
                        "canary_" + c, null);
            }
        }
    }

    private static <T extends Throwable> T with(T finding, String key, Throwable site) {
        StackTraceElement[] base = site != null ? site.getStackTrace() : new Throwable().getStackTrace();
        int skip = site != null ? 0 : 2; // this method and its caller are not interesting
        int n = Math.max(0, Math.min(base.length - skip, 64));
        StackTraceElement[] out = new StackTraceElement[n + 1];
        out[0] = new StackTraceElement("finding." + key.replaceAll("[^A-Za-z0-9_]", "_"), "report", "Findings.java", 1);
        System.arraycopy(base, skip, out, 1, n);
        finding.setStackTrace(out);
        return finding;
    }
}

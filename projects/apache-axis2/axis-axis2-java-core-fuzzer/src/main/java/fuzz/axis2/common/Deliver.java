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

import fuzz.axis2.services.Invoked;

/** Delivers one parsed request to the deployment, through either HTTP transport. */
public final class Deliver {

    private Deliver() {
    }

    public static final class Result {
        public MockHttp.Exchange exchange;
        public String invoked;      // service whose operation actually ran, or null
        public String body = "";
    }

    /**
     * Exceptions that escape the transport are what a servlet container would turn into a 500
     * response and are not findings. Errors (StackOverflowError, OutOfMemoryError) propagate to
     * Jazzer, and so does one that Axis2 caught and logged (see {@link Findings#end()}).
     */
    public static Result run(Env env, HttpInput in, boolean standalone) {
        Result r = new Result();
        Invoked.take();
        Findings.begin();
        try {
            r.exchange = standalone ? env.standalone(in.req) : env.servlet(in.req);
        } catch (Exception e) {
            // expected for malformed requests
        }
        r.invoked = Invoked.take();
        if (r.exchange != null) {
            r.body = r.exchange.resp.bodyString();
        }
        Findings.end();
        return r;
    }
}

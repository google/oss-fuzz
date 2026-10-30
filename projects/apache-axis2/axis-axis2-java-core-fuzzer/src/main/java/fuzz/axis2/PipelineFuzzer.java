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

package fuzz.axis2;

import fuzz.axis2.common.Deliver;
import fuzz.axis2.common.Env;
import fuzz.axis2.common.Findings;
import fuzz.axis2.common.HttpInput;
import fuzz.axis2.common.WatchLog;
import org.apache.axis2.context.ConfigurationContext;

import java.nio.file.Path;

/**
 * The anonymous HTTP request pipeline: AxisServlet (or HTTPWorker, the standalone transport) ->
 * message builders -> dispatchers -> WS-Addressing -> RPCMessageReceiver / data binding ->
 * formatters and faults.
 *
 * Input: a raw HTTP request (see HttpInput); "X-Fuzz-Transport: standalone" selects HTTPWorker.
 * Deployment: the shipped webapp axis2.xml with addressing engaged and the services of
 * Env.deployStandard.
 */
public class PipelineFuzzer {

    static Env env;

    public static void fuzzerInitialize() throws Exception {
        WatchLog.install();
        Path work = Env.workDir("pipeline");
        ConfigurationContext cc = Env.context(new Env.Config("soap"), work);
        Env.deployStandard(cc.getAxisConfiguration(), work);
        env = Env.start(cc, work, "soap");
        env.warmup();
    }

    public static void fuzzerTestOneInput(byte[] data) {
        HttpInput in = HttpInput.parse(data, 1 << 20);
        if (in == null) {
            return;
        }
        Deliver.Result r = Deliver.run(env, in, "standalone".equalsIgnoreCase(in.transport));
        // The Hidden service may legitimately answer in its own namespace when one of its
        // operations ran, so only the other canaries are checked here.
        Findings.canaries(r.body, data, Env.STRICT_CANARIES);
    }
}

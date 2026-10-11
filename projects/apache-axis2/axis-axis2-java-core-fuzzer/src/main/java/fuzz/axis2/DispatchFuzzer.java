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
 * URI dispatch and the anonymous metadata routes (?wsdl, ?wsdl2, ?xsd, ?xsd=..., ?wsdl2=...,
 * /x.xsd, /x.wsdl, listServices) on BOTH transports for every input.
 *
 * Besides Jazzer's own detectors this checks canaries around the Meta service archive
 * (services.xml, keystore.properties, files outside META-INF, outside the archive, or in the
 * parent classloader) and the documentation / namespace of the Hidden service
 * (exposeServiceMetadata=false) while no operation ran.
 */
public class DispatchFuzzer {

    static Env env;

    public static void fuzzerInitialize() throws Exception {
        WatchLog.install();
        Path work = Env.workDir("dispatch");
        ConfigurationContext cc = Env.context(new Env.Config("soap"), work);
        Env.deployStandard(cc.getAxisConfiguration(), work);
        env = Env.start(cc, work, "soap");
        env.warmup();
    }

    public static void fuzzerTestOneInput(byte[] data) {
        for (boolean standalone : new boolean[] {false, true}) {
            HttpInput in = HttpInput.parse(data, 64 * 1024); // fresh body stream per transport
            if (in == null) {
                return;
            }
            Deliver.Result r = Deliver.run(env, in, standalone);
            // When no operation ran, the response is metadata, a listing or a fault: nothing
            // about the hidden service may appear. When one ran, its namespace may appear.
            Findings.canaries(r.body, data, r.invoked == null ? Env.ALL_CANARIES : Env.STRICT_CANARIES);
        }
    }
}

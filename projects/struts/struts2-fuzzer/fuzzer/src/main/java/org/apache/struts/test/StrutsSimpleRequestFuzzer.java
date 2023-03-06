// Copyright 2023 Google LLC
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

package org.apache.struts.test;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;

public class StrutsSimpleRequestFuzzer {
 
    private static String g_host = "localhost";
    private static int g_port = 8080;

    public static void main(String args[]) {
        new StrutsSimpleRequestFuzzer().runTest("hello.action");
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
        new StrutsSimpleRequestFuzzer().runTest(fuzzedDataProvider.consumeRemainingAsString());
    }

    public void runTest(String fuzzyString) {

        Server server = null;

        try {
            server = new Server(g_port);

            // Configure the struts web application ...
            WebAppContext strutsWebApp = new WebAppContext();

            strutsWebApp.setDescriptor("/WEB-INF/web.xml");

            File warFile = new File("struts2-webapp.war");
            strutsWebApp.setWar(warFile.getAbsolutePath());

            strutsWebApp.setContextPath("/struts-test");
            //strutsWebApp.setParentLoaderPriority(true);

            // ... add it to the server configuration in order  to serve requests to /struts-test
            server.setHandler(strutsWebApp);

            // Start the server.
            do {
                try {
                    server.start();
                } catch (Exception ex) {
                    /* port still locked? */
                }
            } while (!server.isStarted());

            HttpURLConnection http = (HttpURLConnection) new URL("http://" + g_host + ":" + g_port + "/struts-test/" + fuzzyString).openConnection();
            http.connect();

            System.out.println(http.getResponseCode() + " " + http.getResponseMessage());

        } catch (IOException ex) {
            /* ignore */
        } catch (IllegalArgumentException ex) {
            /* ignore */
        } finally {

            if (server != null) {
                do {
                    try {
                        server.stop();
                    } catch (Exception ex) {
                        /* shouldn't happen */
                    }
                } while (!server.isStopped());
            }
        }
    }
}

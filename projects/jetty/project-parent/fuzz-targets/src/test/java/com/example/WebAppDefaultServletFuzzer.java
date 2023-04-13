// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////

package com.example;


import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;
import org.junit.jupiter.api.BeforeAll;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;


public class WebAppDefaultServletFuzzer
{

    static Server server;
    static LocalConnector connector;

    @BeforeAll
    static void prepareServer() throws Exception
    {
        server = new Server();
        connector = new LocalConnector(server);
        connector.getConnectionFactory(HttpConnectionFactory.class).getHttpConfiguration().setUriCompliance(UriCompliance.RFC3986);
        server.addConnector(connector);

        Path directoryPath = Files.createTempDirectory("test");
        Path welcomeResource = directoryPath.resolve("index.html");
        try (OutputStream output = Files.newOutputStream(welcomeResource))
        {
            output.write("<h1>welcome page</h1>".getBytes(StandardCharsets.UTF_8));
        }

        WebAppContext context = new WebAppContext(server, directoryPath.toString(), "/");
        server.setHandler(context);
    }


    @FuzzTest
    public void testResourceService3(FuzzedDataProvider data) throws Exception
    {
        server.start();
        String request =
                "GET " + data.consumeRemainingAsString() + " HTTP/1.1\r\n" +
                        "Host: localhost\r\n" +
                        "Connection: close\r\n" +
                        "\r\n";
        connector.getResponse(request);
        try {
            server.stop();
        } catch (Exception e) {
            throw new RuntimeException("Server stop error!");
        }
    }
}

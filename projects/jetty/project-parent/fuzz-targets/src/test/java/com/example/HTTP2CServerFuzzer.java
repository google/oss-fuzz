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
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class HTTP2CServerFuzzer extends AbstractServerTest
{
    @BeforeEach
    public void before() throws Exception
    {
        server = new HTTP2CServer(0);
        server.start();
        connector = (ServerConnector)server.getConnectors()[0];
    }

    @AfterEach
    public void after() throws Exception
    {
        server.stop();
    }

    @FuzzTest
    public void fuzzHTTP(FuzzedDataProvider data) throws Exception
    {
        try (Socket client = new Socket("localhost", connector.getLocalPort()))
        {
            client.getOutputStream().write(data.consumeRemainingAsString().getBytes(StandardCharsets.ISO_8859_1));
            client.getOutputStream().flush();
        }
    }

}

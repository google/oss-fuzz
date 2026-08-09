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
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.util.BytesRequestContent;
import org.eclipse.jetty.server.handler.AbstractHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;


public class HttpClientFuzzer extends AbstractHttpClientServerTest {

    @FuzzTest
    public void testPOSTWithParametersWithContent1(FuzzedDataProvider data) throws Exception {
        Scenario scenario = new NormalScenario();
        String name = data.consumeString(50);
        String value = data.consumeString(50);
        byte[] content = data.consumeRemainingAsBytes();
        if (content.length > 0) {

            String paramName = name;
            String paramValue = value;
            start(scenario, new AbstractHandler() {
                @Override
                public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
                    baseRequest.setHandled(true);
                    consume(request.getInputStream(), true);
                    String value = request.getParameter(paramName);
                    if (paramValue.equals(value)) {
                        response.setCharacterEncoding("UTF-8");
                        response.setContentType("text/plain");
                        response.getOutputStream().write(content);
                    }
                }
            });

            ContentResponse response = client.POST(scenario.getScheme() + "://localhost:" + connector.getLocalPort() + "/?b=1")
                    .param(paramName, paramValue)
                    .body(new BytesRequestContent(content))
                    .timeout(5, TimeUnit.SECONDS)
                    .send();

            response.getStatus();
            response.getContent();

            disposeServer();
            disposeClient();
        }

    }

    private void consume(InputStream input, boolean eof) throws IOException {
        int crlfs = 0;
        while (true) {
            int read = input.read();
            if (read == '\r' || read == '\n')
                ++crlfs;
            else
                crlfs = 0;
            if (!eof && crlfs == 4)
                break;
            if (read < 0)
                break;
        }
    }

}

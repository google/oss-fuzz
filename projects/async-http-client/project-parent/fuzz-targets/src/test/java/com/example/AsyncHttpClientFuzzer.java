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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.asynchttpclient.Response;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.util.HttpConstants;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.util.*;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.util.concurrent.ExecutionException;

import static org.asynchttpclient.Dsl.*;

class AsyncHttpClientFuzzer {
    static Server server;
    static int port1 = -1;

    static String [] methods = {
            HttpConstants.Methods.CONNECT,
            HttpConstants.Methods.DELETE,
            HttpConstants.Methods.GET,
            HttpConstants.Methods.HEAD,
            HttpConstants.Methods.OPTIONS,
            HttpConstants.Methods.PATCH,
            HttpConstants.Methods.POST,
            HttpConstants.Methods.PUT,
            HttpConstants.Methods.TRACE
    };

    @BeforeAll
    static void setUp() {
        server = new Server();
        ServerConnector connector1 = addHttpConnector(server);
        try {
            server.start();
        } catch (Exception e) {
            return;
        }
        port1 = connector1.getLocalPort();
    }

    @AfterAll
    static void cleanUp() {
        if (server != null) {
            try {
                server.stop();
            } catch (Exception e) {
            }
        }
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try (AsyncHttpClient client = asyncHttpClient()) {
            HttpHeaders httpHeaders = new DefaultHttpHeaders();

            for (int i = 0; i < data.consumeInt(0, 50); ++i) {
                httpHeaders.add(data.consumeString(500), data.consumeString(500));
            }

            Map<String, List<String>> formParams = new HashMap<>();
            for (int i = 0; i < data.consumeInt(0, 50); i++) {
                formParams.put(data.consumeString(500), Collections.singletonList(data.consumeString(500)));
            }

            Map<String, List<String>> queryParams = new HashMap<>();
            for (int i = 0; i < data.consumeInt(0, 50); i++) {
                queryParams.put(data.consumeString(500), Collections.singletonList(data.consumeString(500)));
            }

            Collection<io.netty.handler.codec.http.cookie.Cookie> cookies = new ArrayList<>();
            for (int i = 0; i < data.consumeInt(0, 50); i++) {
                io.netty.handler.codec.http.cookie.Cookie cookie = new DefaultCookie(data.consumeString(500), data.consumeString(500));
                cookie.setDomain(data.consumeString(500));
                cookie.setPath(data.consumeString(500));
                cookie.setMaxAge(data.consumeInt());
                cookie.setSecure(data.consumeBoolean());
                cookie.setHttpOnly(data.consumeBoolean());
                cookies.add(cookie);
            }

            Response resp = client.prepare(data.pickValue(methods), data.consumeString(500))
                    .setCookies(cookies)
                    .setHeaders(httpHeaders)
                    .setFormParams(formParams)
                    .setQueryParams(queryParams)
                    .setVirtualHost(data.consumeString(500))
                    .setBody(new ByteArrayInputStream(data.consumeRemainingAsBytes()))
                    .execute()
                    .get();
        } catch (IOException | InterruptedException | ExecutionException | IllegalArgumentException | IllegalStateException e) {
        }
    }

    public static ServerConnector addHttpConnector(Server server) {
        ServerConnector connector = new ServerConnector(server);
        server.addConnector(connector);
        return connector;
    }
}
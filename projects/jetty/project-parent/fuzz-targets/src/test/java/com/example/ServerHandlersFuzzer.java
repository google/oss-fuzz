// Copyright 2022 Google LLC
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
import org.eclipse.jetty.io.NullByteBufferPool;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.*;
import org.junit.jupiter.api.BeforeAll;

import java.util.Collection;


class ServerHandlersFuzzer {
    static Server _server;
    static LocalConnector _connector;
    static HandlerCollection handlers;
    static String[] methods_arr = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"};
    static Handler[] handler_arr = {new AsyncDelayHandler(), new BufferedResponseHandler(), new ContextHandler(), new DefaultHandler(), new ErrorHandler(), new FileBufferedResponseHandler(),
            new HotSwapHandler(), new IdleTimeoutHandler(), new InetAccessHandler(), new MovedContextHandler(), new RequestLogHandler(), new ResourceHandler(), new SecuredRedirectHandler(),
            new ThreadLimitHandler()};

    @BeforeAll
    static void setup() {
        _server = new Server();
        _server.addBean(new NullByteBufferPool());
        _connector = new LocalConnector(_server, new HttpConnectionFactory(), null);
        _connector.setIdleTimeout(3000);
        _server.addConnector(_connector);
    }

    @FuzzTest
    void getResponse(FuzzedDataProvider data) {
        Collection<Handler> handlersCollection = data.pickValues(handler_arr, data.consumeInt(0, handler_arr.length));
        String method = data.pickValue(methods_arr);
        String str = data.consumeString(1000);
        String str1 = data.consumeString(1000);
        String str2 = data.consumeRemainingAsString();

        handlers = new HandlerCollection();

        for (Handler handler: handlersCollection) {
            handlers.addHandler(handler);
        }

        _server.setHandler(handlers);

        try {
            _server.start();
        } catch (Exception e) {
            throw new RuntimeException("Server start error!");
        }

        try {
            _connector.getResponse(method + " /" + str + " HTTP/1.0\r\n" + str1 + "\r\n\r\n" + str2);
        } catch (Exception e) {
        }

        try {
            _server.stop();
        } catch (Exception e) {
            throw new RuntimeException("Server stop error!");
        }
    }

}
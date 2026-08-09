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

import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class HTTP2CServer extends Server
{
    public HTTP2CServer(int port)
    {
        HttpConfiguration config = new HttpConfiguration();
        // HTTP + HTTP/2 connector

        HttpConnectionFactory http1 = new HttpConnectionFactory(config);
        HTTP2CServerConnectionFactory http2c = new HTTP2CServerConnectionFactory(config);
        ServerConnector connector = new ServerConnector(this, http1, http2c);
        connector.setPort(port);
        addConnector(connector);

        ((QueuedThreadPool)getThreadPool()).setName("server");

        setHandler(new SimpleHandler());
    }

    public static void main(String... args) throws Exception
    {
        HTTP2CServer server = new HTTP2CServer(8080);
        server.start();
    }

    private static class SimpleHandler extends AbstractHandler
    {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
        {
            baseRequest.setHandled(true);
            String code = request.getParameter("code");
            if (code != null)
                response.setStatus(Integer.parseInt(code));

            response.setHeader("Custom", "Value");
            response.setContentType("text/plain");
            String content = "Hello from Jetty using " + request.getProtocol() + "\n";
            content += "uri=" + request.getRequestURI() + "\n";
            content += "date=" + new Date() + "\n";
            response.setContentLength(content.length());
            response.getOutputStream().print(content);
        }
    }
}

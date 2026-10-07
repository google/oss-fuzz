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

import org.eclipse.jetty.http.*;
import org.eclipse.jetty.http2.api.server.ServerSessionListener;
import org.eclipse.jetty.http2.generator.Generator;
import org.eclipse.jetty.http2.parser.Parser;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.http2.server.RawHTTP2ServerConnectionFactory;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.io.MappedByteBufferPool;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.junit.jupiter.api.AfterEach;

import javax.servlet.http.HttpServlet;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;

public abstract class AbstractServerTest
{
    protected ServerConnector connector;
    protected ByteBufferPool byteBufferPool;
    protected Generator generator;
    protected Server server;
    protected String path;

    protected void startServer(HttpServlet servlet) throws Exception
    {
        prepareServer(new HTTP2ServerConnectionFactory(new HttpConfiguration()));
        ServletContextHandler context = new ServletContextHandler(server, "/");
        context.addServlet(new ServletHolder(servlet), path);
        server.start();
    }

    protected void startServer(ServerSessionListener listener) throws Exception
    {
        prepareServer(new RawHTTP2ServerConnectionFactory(new HttpConfiguration(), listener));
        server.start();
    }

    private void prepareServer(ConnectionFactory connectionFactory)
    {
        QueuedThreadPool serverExecutor = new QueuedThreadPool();
        serverExecutor.setName("server");
        server = new Server(serverExecutor);
        connector = new ServerConnector(server, connectionFactory);
        server.addConnector(connector);
        path = "/test";
        byteBufferPool = new MappedByteBufferPool();
        generator = new Generator(byteBufferPool);
    }

    protected MetaData.Request newRequest(String method, HttpFields fields)
    {
        String host = "localhost";
        int port = connector.getLocalPort();
        String authority = host + ":" + port;
        return new MetaData.Request(method, HttpScheme.HTTP.asString(), new HostPortHttpField(authority), path, HttpVersion.HTTP_2, fields, -1);
    }

    @AfterEach
    public void dispose() throws Exception
    {
        if (server != null)
            server.stop();
    }

    protected boolean parseResponse(Socket client, Parser parser) throws IOException
    {
        return parseResponse(client, parser, 1000);
    }

    protected boolean parseResponse(Socket client, Parser parser, long timeout) throws IOException
    {
        byte[] buffer = new byte[2048];
        InputStream input = client.getInputStream();
        client.setSoTimeout((int)timeout);
        while (true)
        {
            try
            {
                int read = input.read(buffer);
                if (read < 0)
                    return true;
                parser.parse(ByteBuffer.wrap(buffer, 0, read));
                if (client.isClosed())
                    return true;
            }
            catch (SocketTimeoutException x)
            {
                return false;
            }
        }
    }
}

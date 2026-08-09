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

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpClientTransport;
import org.eclipse.jetty.client.http.HttpClientTransportOverHTTP;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.SocketAddressResolver;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.util.thread.ScheduledExecutorScheduler;
import org.eclipse.jetty.util.thread.Scheduler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

public abstract class AbstractHttpClientServerTest
{
    protected Server server;
    protected HttpClient client;
    protected ServerConnector connector;

    public void start(Scenario scenario, Handler handler) throws Exception
    {
        startServer(scenario, handler);
        startClient(scenario);
    }

    protected void startServer(Scenario scenario, Handler handler) throws Exception
    {
        if (server == null)
        {
            QueuedThreadPool serverThreads = new QueuedThreadPool();
            serverThreads.setName("server");
            server = new Server(serverThreads);
        }
        connector = new ServerConnector(server, scenario.newServerSslContextFactory());
        connector.setPort(0);
        server.addConnector(connector);
        server.setHandler(handler);
        server.start();
    }

    protected void startClient(Scenario scenario) throws Exception
    {
        startClient(scenario, null);
    }

    protected void startClient(Scenario scenario, Consumer<HttpClient> config) throws Exception
    {
        startClient(scenario, HttpClientTransportOverHTTP::new, config);
    }

    protected void startClient(Scenario scenario, Function<ClientConnector, HttpClientTransportOverHTTP> transport, Consumer<HttpClient> config) throws Exception
    {
        ClientConnector clientConnector = new ClientConnector();
        clientConnector.setSelectors(1);
        clientConnector.setSslContextFactory(scenario.newClientSslContextFactory());
        QueuedThreadPool executor = new QueuedThreadPool();
        executor.setName("client");
        clientConnector.setExecutor(executor);
        Scheduler scheduler = new ScheduledExecutorScheduler("client-scheduler", false);
        clientConnector.setScheduler(scheduler);
        client = newHttpClient(transport.apply(clientConnector));
        client.setSocketAddressResolver(new SocketAddressResolver.Sync());
        if (config != null)
            config.accept(client);
        client.start();
    }

    public HttpClient newHttpClient(HttpClientTransport transport)
    {
        return new HttpClient(transport);
    }

    @AfterEach
    public void disposeClient() throws Exception
    {
        if (client != null)
        {
            client.stop();
            client = null;
        }
    }

    @AfterEach
    public void disposeServer() throws Exception
    {
        if (server != null)
        {
            server.stop();
            server = null;
        }
    }

    public static class ScenarioProvider implements ArgumentsProvider
    {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context)
        {
            return Stream.of(
                new NormalScenario()
                // TODO: add more ssl / non-ssl scenarios here
            ).map(Arguments::of);
        }
    }


    public interface Scenario
    {
        SslContextFactory.Client newClientSslContextFactory();

        SslContextFactory.Server newServerSslContextFactory();

        String getScheme();
    }

    public static class NormalScenario implements Scenario
    {
        @Override
        public SslContextFactory.Client newClientSslContextFactory()
        {
            return null;
        }

        @Override
        public SslContextFactory.Server newServerSslContextFactory()
        {
            return null;
        }

        @Override
        public String getScheme()
        {
            return HttpScheme.HTTP.asString();
        }

        @Override
        public String toString()
        {
            return "HTTP";
        }
    }

}

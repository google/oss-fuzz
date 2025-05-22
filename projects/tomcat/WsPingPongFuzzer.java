// Copyright 2022 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import org.apache.tomcat.websocket.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.Arrays;

import jakarta.websocket.ClientEndpointConfig;
import jakarta.websocket.ContainerProvider;
import jakarta.websocket.PongMessage;
import jakarta.websocket.Session;
import jakarta.websocket.WebSocketContainer;
import jakarta.websocket.DeploymentException;

import org.apache.catalina.Context;
import org.apache.catalina.servlets.DefaultServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.LifecycleException;
import org.apache.tomcat.websocket.TesterMessageCountClient.TesterEndpoint;
import org.apache.tomcat.websocket.TesterMessageCountClient.TesterProgrammaticEndpoint;


public class WsPingPongFuzzer {
    static Tomcat tomcat = null;
    static Connector connector1 = null;
    static Context ctx = null;
    static WebSocketContainer wsContainer = null;
    static Session wsSession = null;

    public static void fuzzerTearDown() {
        try {
            tomcat.stop();
            tomcat.destroy();
            tomcat = null;
            System.gc();
        } catch (LifecycleException e) {
            throw new FuzzerSecurityIssueLow("Teardown Error!");
        }
    }

    public static void fuzzerInitialize() {
        tomcat = new Tomcat();
        tomcat.setBaseDir("temp");
        ctx = tomcat.addContext("", null);
        ctx.addApplicationListener(TesterEchoServer.Config.class.getName());
        Tomcat.addServlet(ctx, "default", new DefaultServlet());
        ctx.addServletMappingDecoded("/", "default");

        connector1 = tomcat.getConnector();
        connector1.setPort(0);

        try {
            tomcat.start();
        } catch (LifecycleException e) {
            throw new FuzzerSecurityIssueLow("Tomcat Start error!");
        }

        wsContainer = ContainerProvider.getWebSocketContainer();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte [] ba = data.consumeBytes(125);

        ByteBuffer applicationData = ByteBuffer.wrap(ba);

        ClientEndpointConfig clientEndpointConfig = ClientEndpointConfig.Builder.create().build();

        try {
            wsSession = wsContainer.connectToServer(TesterProgrammaticEndpoint.class, clientEndpointConfig, 
                new URI("ws://localhost:" + tomcat.getConnector().getLocalPort() + TesterEchoServer.Config.PATH_ASYNC));
        } catch (URISyntaxException | DeploymentException | IOException e) {
            return;
        }
        
        CountDownLatch latch = new CountDownLatch(1);
        TesterEndpoint tep = (TesterEndpoint) wsSession.getUserProperties().get("endpoint");
        tep.setLatch(latch);

        PongMessageHandler handler = new PongMessageHandler(latch);
        wsSession.addMessageHandler(handler);
        try {
            for (int i = 0; i < 20; ++i) {
                wsSession.getBasicRemote().sendPing(applicationData);
            }
        } catch (IOException e) {
        }

        try {
            boolean latchResult = handler.getLatch().await(10, TimeUnit.SECONDS);
            assert latchResult == true : new FuzzerSecurityIssueLow("latchResult is not true!");
        } catch (InterruptedException e) {
        }

        assert Arrays.equals(applicationData.array(), (handler.getMessages().peek()).getApplicationData().array()) : new FuzzerSecurityIssueLow("Not equal!");

        try {
            wsSession.close();
        } catch (IOException e) {
        }
    }

    public static class PongMessageHandler extends TesterMessageCountClient.BasicHandler<PongMessage> {
        public PongMessageHandler(CountDownLatch latch) {
            super(latch);
        }

        @Override
        public void onMessage(PongMessage message) {
            getMessages().add(message);
            if (getLatch() != null) {
                getLatch().countDown();
            }
        }
    }

}
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import jakarta.websocket.Session;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompDecoder;
import org.springframework.messaging.simp.stomp.StompEncoder;
import org.springframework.web.socket.*;
import org.springframework.web.socket.adapter.standard.StandardWebSocketSession;
import org.springframework.web.socket.messaging.StompSubProtocolHandler;

public class StompSubProtocolHandlerFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        StompSubProtocolHandler handler = new StompSubProtocolHandler();

        handler.setDecoder(new StompDecoder());
        handler.setEncoder(new StompEncoder());

        DummyEventPublisher publisher = new DummyEventPublisher();
        handler.setApplicationEventPublisher(publisher);

        Session nativeSession = Mockito.mock(Session.class);
        Mockito.when(nativeSession.getNegotiatedSubprotocol()).thenReturn(data.consumeString(100));

        StandardWebSocketSession session = Mockito.mock(StandardWebSocketSession.class);
        Mockito.when(session.isOpen()).thenReturn(data.consumeBoolean());
        Mockito.when(session.getId()).thenReturn(data.consumeString(500));
        Mockito.when(session.getAcceptedProtocol()).thenReturn(data.consumeString(500));
        Mockito.when(session.getBinaryMessageSizeLimit()).thenReturn(data.consumeInt());
        Mockito.when(session.getTextMessageSizeLimit()).thenReturn(data.consumeInt());

        session.initializeNativeSession(nativeSession);

        MessageChannel channel = Mockito.mock(MessageChannel.class);
        Mockito.when(channel.send(Mockito.any())).thenReturn(data.consumeBoolean());

        handler.afterSessionStarted(session, channel);

        WebSocketMessage<?> message;
        if (data.consumeBoolean()) {
            message = new TextMessage(data.consumeBytes(1000));
        } else {
            message = new BinaryMessage(data.consumeBytes(1000));
        }

        try {
            handler.handleMessageFromClient(session, message, channel);
        } catch (IllegalStateException | IllegalArgumentException ignored) {}
    }

    public static class DummyEventPublisher implements ApplicationEventPublisher {

        @Override
        public void publishEvent(Object event) {}
    }
}

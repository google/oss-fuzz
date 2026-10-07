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
import jakarta.jms.Destination;
import jakarta.jms.JMSException;
import jakarta.jms.TextMessage;
import org.springframework.jms.support.SimpleJmsHeaderMapper;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;

import java.util.Enumeration;

public class SimpleJmsHeaderMapperFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		SimpleJmsHeaderMapper mapper = new SimpleJmsHeaderMapper();
		if (data.consumeBoolean()) {
			mapper.setOutboundPrefix(data.consumeString(50));
		}

		if (data.consumeBoolean()) {
			mapper.setInboundPrefix(data.consumeString(100));
		}

		MessageBuilder<String> builder = MessageBuilder.withPayload(data.consumeString(100));

		for (int i = 0; i < data.consumeInt(0, 30); i++) {
			addHeader(builder, data);
		}

		Message<String> message = builder.build();

		jakarta.jms.Message jmsMessage = new DummyMessage();
		mapper.fromHeaders(message.getHeaders(), jmsMessage);
	}

	private static void addHeader(MessageBuilder<String> builder, FuzzedDataProvider data) {
		try {
			switch (data.consumeInt(0, 4)) {
				case 0 -> builder.setHeader(data.consumeString(50), data.consumeString(100));
				case 1 -> builder.setHeader(data.consumeString(50), data.consumeInt());
				case 2 -> builder.setHeader(data.consumeString(50), data.consumeLong());
				case 3 -> builder.setHeader(data.consumeString(50), data.consumeBoolean());
				case 4 -> builder.setHeader(data.consumeString(50), data.consumeBytes(50));
			}
		} catch (java.lang.IllegalArgumentException e) {}
	}

	public static class DummyMessage implements TextMessage {

		@Override
		public void setText(String s) throws JMSException {

		}

		@Override
		public String getText() throws JMSException {
			return null;
		}

		@Override
		public String getJMSMessageID() throws JMSException {
			return null;
		}

		@Override
		public void setJMSMessageID(String s) throws JMSException {

		}

		@Override
		public long getJMSTimestamp() throws JMSException {
			return 0;
		}

		@Override
		public void setJMSTimestamp(long l) throws JMSException {

		}

		@Override
		public byte[] getJMSCorrelationIDAsBytes() throws JMSException {
			return new byte[0];
		}

		@Override
		public void setJMSCorrelationIDAsBytes(byte[] bytes) throws JMSException {

		}

		@Override
		public void setJMSCorrelationID(String s) throws JMSException {

		}

		@Override
		public String getJMSCorrelationID() throws JMSException {
			return null;
		}

		@Override
		public Destination getJMSReplyTo() throws JMSException {
			return null;
		}

		@Override
		public void setJMSReplyTo(Destination destination) throws JMSException {

		}

		@Override
		public Destination getJMSDestination() throws JMSException {
			return null;
		}

		@Override
		public void setJMSDestination(Destination destination) throws JMSException {

		}

		@Override
		public int getJMSDeliveryMode() throws JMSException {
			return 0;
		}

		@Override
		public void setJMSDeliveryMode(int i) throws JMSException {

		}

		@Override
		public boolean getJMSRedelivered() throws JMSException {
			return false;
		}

		@Override
		public void setJMSRedelivered(boolean b) throws JMSException {

		}

		@Override
		public String getJMSType() throws JMSException {
			return null;
		}

		@Override
		public void setJMSType(String s) throws JMSException {

		}

		@Override
		public long getJMSExpiration() throws JMSException {
			return 0;
		}

		@Override
		public void setJMSExpiration(long l) throws JMSException {

		}

		@Override
		public long getJMSDeliveryTime() throws JMSException {
			return 0;
		}

		@Override
		public void setJMSDeliveryTime(long l) throws JMSException {

		}

		@Override
		public int getJMSPriority() throws JMSException {
			return 0;
		}

		@Override
		public void setJMSPriority(int i) throws JMSException {

		}

		@Override
		public void clearProperties() throws JMSException {

		}

		@Override
		public boolean propertyExists(String s) throws JMSException {
			return false;
		}

		@Override
		public boolean getBooleanProperty(String s) throws JMSException {
			return false;
		}

		@Override
		public byte getByteProperty(String s) throws JMSException {
			return 0;
		}

		@Override
		public short getShortProperty(String s) throws JMSException {
			return 0;
		}

		@Override
		public int getIntProperty(String s) throws JMSException {
			return 0;
		}

		@Override
		public long getLongProperty(String s) throws JMSException {
			return 0;
		}

		@Override
		public float getFloatProperty(String s) throws JMSException {
			return 0;
		}

		@Override
		public double getDoubleProperty(String s) throws JMSException {
			return 0;
		}

		@Override
		public String getStringProperty(String s) throws JMSException {
			return null;
		}

		@Override
		public Object getObjectProperty(String s) throws JMSException {
			return null;
		}

		@Override
		public Enumeration getPropertyNames() throws JMSException {
			return null;
		}

		@Override
		public void setBooleanProperty(String s, boolean b) throws JMSException {

		}

		@Override
		public void setByteProperty(String s, byte b) throws JMSException {

		}

		@Override
		public void setShortProperty(String s, short i) throws JMSException {

		}

		@Override
		public void setIntProperty(String s, int i) throws JMSException {

		}

		@Override
		public void setLongProperty(String s, long l) throws JMSException {

		}

		@Override
		public void setFloatProperty(String s, float v) throws JMSException {

		}

		@Override
		public void setDoubleProperty(String s, double v) throws JMSException {

		}

		@Override
		public void setStringProperty(String s, String s1) throws JMSException {

		}

		@Override
		public void setObjectProperty(String s, Object o) throws JMSException {

		}

		@Override
		public void acknowledge() throws JMSException {

		}

		@Override
		public void clearBody() throws JMSException {

		}

		@Override
		public <T> T getBody(Class<T> aClass) throws JMSException {
			return null;
		}

		@Override
		public boolean isBodyAssignableTo(Class aClass) throws JMSException {
			return false;
		}
	}
}
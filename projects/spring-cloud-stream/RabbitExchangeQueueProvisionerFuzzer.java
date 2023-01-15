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
import com.rabbitmq.client.BlockedListener;
import com.rabbitmq.client.Channel;
import org.mockito.Mockito;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.connection.Connection;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionListener;
import org.springframework.cloud.stream.binder.ExtendedProducerProperties;
import org.springframework.cloud.stream.binder.rabbit.properties.RabbitProducerProperties;
import org.springframework.cloud.stream.binder.rabbit.provisioning.RabbitExchangeQueueProvisioner;

public class RabbitExchangeQueueProvisionerFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		Channel channel = Mockito.mock(Channel.class);
		Mockito.when(channel.getChannelNumber()).thenReturn(data.consumeInt());

		Connection connection = Mockito.mock(DummyConnection.class);
		Mockito.when(connection.createChannel(Mockito.anyBoolean())).thenReturn(channel);
		Mockito.when(connection.isOpen()).thenReturn(true);

		DummyConnectionFactory connectionFactory = Mockito.mock(DummyConnectionFactory.class);
		Mockito.when(connectionFactory.getPort()).thenReturn(data.consumeInt());
		Mockito.when(connectionFactory.getHost()).thenReturn(data.consumeString(50));
		Mockito.when(connectionFactory.getVirtualHost()).thenReturn(data.consumeString(50));
		Mockito.when(connectionFactory.getUsername()).thenReturn(data.consumeString(50));
		Mockito.when(connectionFactory.getPort()).thenReturn(data.consumeInt());
		Mockito.when(connectionFactory.createConnection()).thenReturn(connection);

		RabbitExchangeQueueProvisioner provisioner = new RabbitExchangeQueueProvisioner(connectionFactory);
		if (data.consumeBoolean()) {
			RabbitProducerProperties rabbitProducerProperties = new RabbitProducerProperties();
			rabbitProducerProperties.setCompress(data.consumeBoolean());
			rabbitProducerProperties.setHeaderPatterns(new String[]{data.consumeString(100)});
			rabbitProducerProperties.setBatchingEnabled(data.consumeBoolean());
			rabbitProducerProperties.setRoutingKey(data.consumeString(100));
			rabbitProducerProperties.setConfirmAckChannel(data.consumeString(100));
			rabbitProducerProperties.setUseConfirmHeader(data.consumeBoolean());
			rabbitProducerProperties.setStreamMessageConverterBeanName(data.consumeString(100));
			rabbitProducerProperties.setSuperStream(data.consumeBoolean());
			rabbitProducerProperties.setBatchingStrategyBeanName(data.consumeString(100));

			ExtendedProducerProperties<RabbitProducerProperties> properties = new ExtendedProducerProperties<RabbitProducerProperties>(rabbitProducerProperties);
			provisioner.provisionProducerDestination(data.consumeString(500), properties);
		}
	}

	public class DummyConnection implements Connection {

		@Override
		public Channel createChannel(boolean b) throws AmqpException {
			return null;
		}

		@Override
		public void close() throws AmqpException {

		}

		@Override
		public boolean isOpen() {
			return false;
		}

		@Override
		public int getLocalPort() {
			return 0;
		}

		@Override
		public void addBlockedListener(BlockedListener blockedListener) {

		}

		@Override
		public boolean removeBlockedListener(BlockedListener blockedListener) {
			return false;
		}
	}

	public class DummyConnectionFactory implements ConnectionFactory {

		@Override
		public Connection createConnection() throws AmqpException {
			return null;
		}

		@Override
		public String getHost() {
			return null;
		}

		@Override
		public int getPort() {
			return 0;
		}

		@Override
		public String getVirtualHost() {
			return null;
		}

		@Override
		public String getUsername() {
			return null;
		}

		@Override
		public void addConnectionListener(ConnectionListener connectionListener) {

		}

		@Override
		public boolean removeConnectionListener(ConnectionListener connectionListener) {
			return false;
		}

		@Override
		public void clearConnectionListeners() {

		}
	}
}

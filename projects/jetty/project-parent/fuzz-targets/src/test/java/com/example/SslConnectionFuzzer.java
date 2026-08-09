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
import org.eclipse.jetty.io.*;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.toolchain.test.MavenTestingUtils;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.FutureCallback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.util.thread.Scheduler;
import org.eclipse.jetty.util.thread.TimerScheduler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class SslConnectionFuzzer
{
    private static final Logger LOG = LoggerFactory.getLogger(SslConnectionFuzzer.class);

    private static final int TIMEOUT = 1000000;
    private static ByteBufferPool __byteBufferPool = new LeakTrackingByteBufferPool(new MappedByteBufferPool.Tagged());

    private final SslContextFactory _sslCtxFactory = new SslContextFactory.Server();
    protected volatile EndPoint _lastEndp;
    private volatile boolean _testFill = true;
    private volatile boolean _onXWriteThenShutdown = false;

    private volatile FutureCallback _writeCallback;
    protected ServerSocketChannel _connector;
    final AtomicInteger _dispatches = new AtomicInteger();
    protected QueuedThreadPool _threadPool = new QueuedThreadPool()
    {
        @Override
        public void execute(Runnable job)
        {
            _dispatches.incrementAndGet();
            super.execute(job);
        }
    };
    protected Scheduler _scheduler = new TimerScheduler();
    protected SelectorManager _manager = new SelectorManager(_threadPool, _scheduler)
    {
        @Override
        public Connection newConnection(SelectableChannel channel, EndPoint endpoint, Object attachment)
        {
            SSLEngine engine = _sslCtxFactory.newSSLEngine();
            engine.setUseClientMode(false);
            SslConnection sslConnection = new SslConnection(__byteBufferPool, getExecutor(), endpoint, engine);
            sslConnection.setRenegotiationAllowed(_sslCtxFactory.isRenegotiationAllowed());
            sslConnection.setRenegotiationLimit(_sslCtxFactory.getRenegotiationLimit());
            Connection appConnection = new TestConnection(sslConnection.getDecryptedEndPoint());
            sslConnection.getDecryptedEndPoint().setConnection(appConnection);
            return sslConnection;
        }

        @Override
        protected EndPoint newEndPoint(SelectableChannel channel, ManagedSelector selector, SelectionKey selectionKey)
        {
            SocketChannelEndPoint endp = new TestEP(channel, selector, selectionKey, getScheduler());
            endp.setIdleTimeout(TIMEOUT);
            _lastEndp = endp;
            return endp;
        }
    };

    static final AtomicInteger __startBlocking = new AtomicInteger();
    static final AtomicInteger __blockFor = new AtomicInteger();
    static final AtomicBoolean __onIncompleteFlush = new AtomicBoolean();

    private static class TestEP extends SocketChannelEndPoint
    {
        public TestEP(SelectableChannel channel, ManagedSelector selector, SelectionKey key, Scheduler scheduler)
        {
            super((SocketChannel)channel, selector, key, scheduler);
        }

        @Override
        protected void onIncompleteFlush()
        {
            __onIncompleteFlush.set(true);
        }

        @Override
        public boolean flush(ByteBuffer... buffers) throws IOException
        {
            __onIncompleteFlush.set(false);
            if (__startBlocking.get() == 0 || __startBlocking.decrementAndGet() == 0)
            {
                if (__blockFor.get() > 0 && __blockFor.getAndDecrement() > 0)
                {
                    return false;
                }
            }
            return super.flush(buffers);
        }
    }

    @BeforeEach
    public void initSSL() throws Exception
    {
        File keystore = MavenTestingUtils.getTestResourceFile("keystore.p12");
        _sslCtxFactory.setKeyStorePath(keystore.getAbsolutePath());
        _sslCtxFactory.setKeyStorePassword("storepwd");
        _sslCtxFactory.setRenegotiationAllowed(true);
        _sslCtxFactory.setRenegotiationLimit(-1);
        startManager();
    }

    public void startManager() throws Exception
    {
        _testFill = true;
        _writeCallback = null;
        _lastEndp = null;
        _connector = ServerSocketChannel.open();
        _connector.socket().bind(null);
        _threadPool.start();
        _scheduler.start();
        _manager.start();
    }

    private void startSSL() throws Exception
    {
        _sslCtxFactory.start();
    }

    @AfterEach
    public void stopSSL() throws Exception
    {
        stopManager();
        _sslCtxFactory.stop();
    }

    private void stopManager() throws Exception
    {
        if (_lastEndp != null && _lastEndp.isOpen())
            _lastEndp.close();
        _manager.stop();
        _scheduler.stop();
        _threadPool.stop();
        _connector.close();
    }

    public class TestConnection extends AbstractConnection
    {
        ByteBuffer _in = BufferUtil.allocate(8 * 1024);

        public TestConnection(EndPoint endp)
        {
            super(endp, _threadPool);
        }

        @Override
        public void onOpen()
        {
            super.onOpen();
            if (_testFill)
                fillInterested();
            else
            {
                getExecutor().execute(() -> getEndPoint().write(_writeCallback, BufferUtil.toBuffer("Hello Client")));
            }
        }

        @Override
        public void onClose(Throwable cause)
        {
            super.onClose(cause);
        }

        @Override
        public void onFillable()
        {
            EndPoint endp = getEndPoint();
            try
            {
                boolean progress = true;
                while (progress)
                {
                    progress = false;

                    // Fill the input buffer with everything available
                    int filled = endp.fill(_in);
                    while (filled > 0)
                    {
                        progress = true;
                        filled = endp.fill(_in);
                    }

                    boolean shutdown = _onXWriteThenShutdown && BufferUtil.toString(_in).contains("X");

                    // Write everything
                    int l = _in.remaining();
                    if (l > 0)
                    {
                        FutureCallback blockingWrite = new FutureCallback();

                        endp.write(blockingWrite, _in);
                        blockingWrite.get();
                        if (shutdown)
                            endp.shutdownOutput();
                    }

                    // are we done?
                    if (endp.isInputShutdown() || shutdown)
                        endp.shutdownOutput();
                }
            }
            catch (InterruptedException | EofException e)
            {
                LOG.trace("IGNORED", e);
            }
            catch (Exception e)
            {
                LOG.warn("During onFillable", e);
            }
            finally
            {
                if (endp.isOpen())
                    fillInterested();
            }
        }
    }

    protected SSLSocket newClient() throws IOException
    {
        SSLSocket socket = _sslCtxFactory.newSslSocket();
        socket.connect(_connector.socket().getLocalSocketAddress());
        return socket;
    }

    @FuzzTest
    public void fuzz(FuzzedDataProvider data) throws Exception
    {
        startSSL();
        try (Socket client = newClient())
        {
            client.setSoTimeout(TIMEOUT);
            try (SocketChannel server = _connector.accept())
            {
                server.configureBlocking(false);
                _manager.accept(server);
                client.getOutputStream().write(data.consumeString(10).getBytes(StandardCharsets.UTF_8));
                client.getOutputStream().write(data.consumeRemainingAsString().getBytes(StandardCharsets.UTF_8));
            }
        }
    }
}

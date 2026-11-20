/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests that {@link SocketNode} rejects logging events carrying nested
 * collections (CVE-2023-26464) instead of spending exponential time
 * deserializing them.
 */
public class SocketNodeTest extends TestCase {

    private Hierarchy hierarchy;
    private VectorAppender appender;

    protected void setUp() {
        hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        appender = new VectorAppender();
        hierarchy.getRootLogger().addAppender(appender);
    }

    /**
     * Sends a regular event followed by an event whose MDC holds the given
     * payload, and checks that the regular event is logged while the
     * connection is closed on the malicious one.
     */
    private void assertPayloadRejected(Object payload) throws Exception {
        ServerSocket serverSocket = new ServerSocket(0);
        Socket client = null;
        try {
            client = new Socket("localhost", serverSocket.getLocalPort());
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            oos.flush();

            Thread node = new Thread(new SocketNode(serverSocket.accept(), hierarchy));
            node.setDaemon(true);
            node.start();

            oos.writeObject(HardenedObjectInputStreamTest.createEvent("regular event", "value"));
            oos.flush();
            oos.reset();
            try {
                oos.writeObject(HardenedObjectInputStreamTest.createEvent("malicious event", payload));
                oos.flush();
            } catch (IOException e) {
                // SocketNode may close the connection before the whole event is sent
            }

            node.join(HardenedObjectInputStreamTest.TIMEOUT);
            assertFalse("SocketNode should close the connection on nested collections", node.isAlive());
            assertEquals(1, appender.getVector().size());
        } finally {
            if (client != null) {
                client.close();
            }
            serverSocket.close();
        }
    }

    public void testNestedHashSetEventRejected() throws Exception {
        assertPayloadRejected(HardenedObjectInputStreamTest.createNestedHashSetPayload());
    }

    public void testSharedNestedListEventRejected() throws Exception {
        assertPayloadRejected(HardenedObjectInputStreamTest.createSharedListPayload());
    }

    public void testNestedMapEntryEventRejected() throws Exception {
        assertPayloadRejected(HardenedObjectInputStreamTest.createNestedMapEntryPayload());
    }
}

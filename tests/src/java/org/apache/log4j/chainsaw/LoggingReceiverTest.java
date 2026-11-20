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
package org.apache.log4j.chainsaw;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import junit.framework.TestCase;

import org.apache.log4j.net.HardenedObjectInputStreamTest;

/**
 * Tests that the Chainsaw {@link LoggingReceiver} rejects logging events
 * carrying nested collections (CVE-2023-26464) instead of spending
 * exponential time deserializing them.
 */
public class LoggingReceiverTest extends TestCase {

    private static int findFreePort() throws IOException {
        ServerSocket socket = new ServerSocket(0);
        try {
            return socket.getLocalPort();
        } finally {
            socket.close();
        }
    }

    /**
     * Sends a regular event followed by an event whose MDC holds the given
     * payload, and checks that the regular event is received while the
     * connection is closed on the malicious one.
     */
    private void assertPayloadRejected(Object payload) throws Exception {
        MyTableModel model = new MyTableModel();
        int port = findFreePort();
        LoggingReceiver receiver = new LoggingReceiver(model, port);
        receiver.start();

        Socket client = new Socket("localhost", port);
        try {
            client.setSoTimeout((int) HardenedObjectInputStreamTest.TIMEOUT);
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            oos.writeObject(HardenedObjectInputStreamTest.createEvent("regular event", "value"));
            oos.flush();
            oos.reset();
            try {
                oos.writeObject(HardenedObjectInputStreamTest.createEvent("malicious event", payload));
                oos.flush();
            } catch (IOException e) {
                // the receiver may close the connection before the whole event is sent
            }

            try {
                assertEquals(-1, client.getInputStream().read());
            } catch (SocketTimeoutException e) {
                fail("LoggingReceiver should close the connection on nested collections");
            } catch (SocketException e) {
                // connection reset by the receiver
            }
        } finally {
            client.close();
        }

        long deadline = System.currentTimeMillis() + HardenedObjectInputStreamTest.TIMEOUT;
        while (model.getRowCount() < 1 && System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
        assertEquals(1, model.getRowCount());
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

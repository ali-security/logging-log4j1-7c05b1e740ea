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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /** Upper bound for reading a payload that must be rejected quickly. */
    public static final long TIMEOUT = 10000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Builds the CVE-2023-26464 attack payload: deeply nested HashSets
     * that form a DAG causing O(2^N) hashCode() computation.
     */
    public static Set createNestedHashSetPayload() {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    /**
     * Builds a HashSet whose element unfolds into 1000^5 nested lists while
     * being made of only a handful of distinct collections: each list
     * references the next one 1000 times.
     */
    public static Set createSharedListPayload() {
        List current = new ArrayList();
        current.add("foo");
        for (int i = 0; i < 5; i++) {
            List parent = new ArrayList();
            for (int j = 0; j < 1000; j++) {
                parent.add(current);
            }
            current = parent;
        }
        return hashedOnRead(current);
    }

    /**
     * Builds a HashSet whose element is a chain of 100 Map.Entry objects,
     * each using the next one as both key and value.
     */
    public static Set createNestedMapEntryPayload() {
        Map.Entry current = new AbstractMap.SimpleEntry("foo", "bar");
        for (int i = 0; i < 100; i++) {
            Map.Entry parent = new AbstractMap.SimpleEntry(current, null);
            parent.setValue(current);
            current = parent;
        }
        return hashedOnRead(current);
    }

    /**
     * Wraps the given object so that it is hashed when deserialized but
     * not while the payload is built.
     */
    private static Set hashedOnRead(Object obj) {
        List holder = new ArrayList();
        Set set = new HashSet();
        set.add(holder);
        holder.add(obj);
        return set;
    }

    /**
     * Creates a logging event whose MDC holds the given value.
     */
    public static LoggingEvent createEvent(String message, Object mdcValue) {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        if (mdcValue != null) {
            MDC.put("payload", mdcValue);
        }
        try {
            LoggingEvent event = new LoggingEvent(Logger.class.getName(), logger, Level.INFO, message, null);
            event.getMDCCopy();
            return event;
        } finally {
            MDC.remove("payload");
        }
    }

    /**
     * Reads the payload on a separate thread so that a regression shows up
     * as a test failure rather than as a hung build, and returns what the
     * read threw.
     */
    private Throwable readOnSeparateThread(byte[] serialized) throws Exception {
        final HardenedObjectInputStream hois =
            new HardenedObjectInputStream(new ByteArrayInputStream(serialized), new String[0]);
        final Throwable[] thrown = new Throwable[1];
        Thread reader = new Thread() {
            public void run() {
                try {
                    hois.readAdaptedObject();
                } catch (Throwable t) {
                    thrown[0] = t;
                }
            }
        };
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT);
        assertFalse("Deserialization of the nested collection payload did not finish", reader.isAlive());
        hois.close();
        return thrown[0];
    }

    private void assertCollectionLimitExceeded(Throwable thrown) {
        assertNotNull("Nested collection payload should be rejected", thrown);
        assertTrue("Unexpected exception: " + thrown, thrown instanceof InvalidObjectException);
        assertTrue("Should mention collection limit",
                thrown.getMessage().indexOf("collection") != -1);
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        byte[] serialized = serialize(createNestedHashSetPayload());

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") != -1);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A few lists referencing each other many times stay below the count
     * of distinct collections but still cause exponential hashCode()
     * computation; they must be rejected as well.
     */
    public void testSharedNestedListsRejected() throws Exception {
        assertCollectionLimitExceeded(readOnSeparateThread(serialize(createSharedListPayload())));
    }

    /**
     * Nested Map.Entry objects hash their key and value just like
     * collections do and must be limited as well.
     */
    public void testNestedMapEntriesRejected() throws Exception {
        assertCollectionLimitExceeded(readOnSeparateThread(serialize(createNestedMapEntryPayload())));
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * A collection referenced a few times from another one is fine.
     */
    public void testSharedCollectionsWithinLimitAllowed() throws Exception {
        Hashtable shared = new Hashtable();
        shared.put("user", "alice");
        List list = new ArrayList();
        for (int i = 0; i < 10; i++) {
            list.add(shared);
        }
        Set set = new HashSet();
        set.add(list);

        HardenedObjectInputStream hois =
            new HardenedObjectInputStream(new ByteArrayInputStream(serialize(set)), new String[0]);
        Set result = (Set) hois.readAdaptedObject();
        hois.close();

        List resultList = (List) result.iterator().next();
        assertEquals(10, resultList.size());
        assertSame(resultList.get(0), resultList.get(9));
        assertEquals("alice", ((Hashtable) resultList.get(0)).get("user"));
    }

    /**
     * Each event read through readAdaptedObject gets its own budget, so a
     * connection may carry any number of events.
     */
    public void testReadAdaptedObjectResetsLimitPerEvent() throws Exception {
        int eventCount = 2 * HardenedObjectInputStream.MAX_COLLECTION_COUNT;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < eventCount; i++) {
            Hashtable value = new Hashtable();
            value.put("index", String.valueOf(i));
            oos.writeObject(createEvent("event " + i, value));
            oos.reset();
        }
        oos.close();

        HardenedLoggingEventInputStream hleis =
            new HardenedLoggingEventInputStream(new ByteArrayInputStream(bos.toByteArray()));
        for (int i = 0; i < eventCount; i++) {
            LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
            assertEquals("event " + i, event.getRenderedMessage());
            assertEquals(String.valueOf(i), ((Hashtable) event.getMDC("payload")).get("index"));
        }
        hleis.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }
}

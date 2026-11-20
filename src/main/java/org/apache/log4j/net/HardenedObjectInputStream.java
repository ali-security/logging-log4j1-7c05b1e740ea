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
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * HardenedObjectInputStream restricts the set of classes that can be
 * deserialized to a set of explicitly whitelisted classes. This prevents
 * certain type of attacks from being successful.
 * 
 * <p>
 * It is assumed that classes in the "java.lang" and "java.util" packages are
 * always authorized.
 * </p>
 * 
 * @author Ceki G&uuml;lc&uuml;
 * @since 1.2.18
 * 
 *        === Copied from the logback project with permission ==
 */
public class HardenedObjectInputStream extends ObjectInputStream {

	static final String ARRAY_CLASS_PREFIX = "[L";
	final List whitelistedClassNames;
	final static String[] JAVA_PACKAGES = new String[] { "java.lang", "java.util", ARRAY_CLASS_PREFIX + "java.lang" };

	/**
	 * Maximum number of Map/Collection instances allowed during deserialization
	 * of a single object graph. This mitigates CVE-2023-26464 where deeply
	 * nested hash-based collections cause exponential hashCode() computation.
	 *
	 * With N collection objects, the worst-case hashCode cost is O(2^(N/2)).
	 * A limit of 32 bounds this to O(2^16) = ~65K operations.
	 * A normal LoggingEvent has 1-2 collections (MDC Hashtable, properties).
	 *
	 * The same limit also applies to the number of collection occurrences
	 * reachable from a single collection when shared references are followed
	 * (i.e. the number of collections its hashCode() visits), so that a few
	 * collections referencing each other many times cannot bypass it.
	 */
	static final int MAX_COLLECTION_COUNT = 32;

	private int collectionCount = 0;

	/**
	 * Collection occurrences reachable from each Map/Collection/Map.Entry
	 * resolved so far, keyed by identity.
	 */
	private final Map collectionWeights = new IdentityHashMap();

	public HardenedObjectInputStream(InputStream in, String[] whilelist) throws IOException {
		super(in);
		enableResolveObject(true);

		this.whitelistedClassNames = new ArrayList();
		if (whilelist != null) {
			for (int i = 0; i < whilelist.length; i++) {
				this.whitelistedClassNames.add(whilelist[i]);
			}
		}
	}

	public HardenedObjectInputStream(InputStream in, List whitelist) throws IOException {
		super(in);
		enableResolveObject(true);

		this.whitelistedClassNames = new ArrayList();
		this.whitelistedClassNames.addAll(whitelist);
	}

	protected Class resolveClass(ObjectStreamClass anObjectStreamClass) throws IOException, ClassNotFoundException {

		String incomingClassName = anObjectStreamClass.getName();

		if (!isWhitelisted(incomingClassName)) {
			throw new InvalidClassException("Unauthorized deserialization attempt", incomingClassName);
		}

		return super.resolveClass(anObjectStreamClass);
	}

	private boolean isWhitelisted(String incomingClassName) {
		for (int i = 0; i < JAVA_PACKAGES.length; i++) {
			if (incomingClassName.startsWith(JAVA_PACKAGES[i]))
				return true;
		}
		for (int i = 0; i < whitelistedClassNames.size(); i++) {
			String whiteListed = (String) whitelistedClassNames.get(i);
			if (incomingClassName.equals(whiteListed))
				return true;
		}
		return false;
	}

	/**
	 * Reads an object from the stream, resetting the collection counter
	 * so that each top-level readObject call gets its own budget.
	 * Callers should use this instead of {@link #readObject()} directly
	 * when reading multiple objects from the same stream.
	 */
	public Object readAdaptedObject() throws IOException, ClassNotFoundException {
		collectionCount = 0;
		collectionWeights.clear();
		return readObject();
	}

	/**
	 * Counts Map, Collection and Map.Entry instances during deserialization to prevent
	 * CVE-2023-26464: deeply nested hash-based collections cause exponential
	 * hashCode() computation during deserialization.
	 *
	 * Collections are resolved once fully read, i.e. before they are hashed
	 * by an enclosing hash-based collection.
	 */
	protected Object resolveObject(Object obj) throws IOException {
		if (isCollection(obj)) {
			collectionCount++;
			if (collectionCount > MAX_COLLECTION_COUNT) {
				throw collectionLimitExceeded();
			}
			collectionWeights.put(obj, new Integer(computeWeight(obj)));
		}
		return super.resolveObject(obj);
	}

	private static boolean isCollection(Object obj) {
		return obj instanceof Map || obj instanceof Collection || obj instanceof Map.Entry;
	}

	/**
	 * Returns the number of collection occurrences reachable from the given
	 * collection, counting a shared collection once per reference to it.
	 */
	private int computeWeight(Object collection) throws InvalidObjectException {
		int weight = 1;
		if (collection instanceof Map) {
			Iterator it = ((Map) collection).entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry entry = (Map.Entry) it.next();
				weight = addWeight(weight, entry.getKey());
				weight = addWeight(weight, entry.getValue());
			}
		} else if (collection instanceof Collection) {
			Iterator it = ((Collection) collection).iterator();
			while (it.hasNext()) {
				weight = addWeight(weight, it.next());
			}
		} else {
			Map.Entry entry = (Map.Entry) collection;
			weight = addWeight(weight, entry.getKey());
			weight = addWeight(weight, entry.getValue());
		}
		return weight;
	}

	private int addWeight(int weight, Object element) throws InvalidObjectException {
		if (!isCollection(element)) {
			return weight;
		}
		Integer elementWeight = (Integer) collectionWeights.get(element);
		// a collection that is not resolved yet is an enclosing one still being read
		weight += (elementWeight == null) ? 1 : elementWeight.intValue();
		if (weight > MAX_COLLECTION_COUNT) {
			throw collectionLimitExceeded();
		}
		return weight;
	}

	private static InvalidObjectException collectionLimitExceeded() {
		return new InvalidObjectException(
			"Exceeded maximum number of collection objects during deserialization: "
			+ MAX_COLLECTION_COUNT
			+ ". Possible CVE-2023-26464 attack via nested collections.");
	}

	protected void addToWhitelist(List additionalAuthorizedClasses) {
		whitelistedClassNames.addAll(additionalAuthorizedClasses);
	}
}
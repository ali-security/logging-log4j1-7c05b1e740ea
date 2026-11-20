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
package org.apache.log4j;

import java.io.StringReader;
import java.util.Enumeration;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.xml.DOMConfigurator;

/**
 * Regression tests for sonatype-2010-0053 (DLL preloading).
 *
 * <p>The Windows-only NTEventLogAppender called System.loadLibrary from its
 * static initializer, so loading the class, or merely referencing it from a
 * configuration file, made the JVM search the library path (including the
 * current working directory on Windows) for NTEventLogAppender*.dll and run
 * whatever DLL was found there. The appender has been removed; these tests
 * make sure no code path can load it and trigger the native library load.
 */
public class NTEventLogAppenderRemovedTest extends TestCase {

  private static final String NT_APPENDER_CLASS =
          "org.apache.log4j.nt.NTEventLogAppender";

  public NTEventLogAppenderRemovedTest(final String name) {
    super(name);
  }

  public void setUp() {
    LogManager.resetConfiguration();
  }

  public void tearDown() {
    LogManager.resetConfiguration();
  }

  /**
   * Loading the appender class must not be possible, so its static
   * initializer (System.loadLibrary) can never run.
   */
  public void testNTEventLogAppenderClassIsNotAvailable() {
    try {
      Class.forName(NT_APPENDER_CLASS);
      fail(NT_APPENDER_CLASS + " must not be available");
    } catch (ClassNotFoundException expected) {
      // the vulnerable appender has been removed
    } catch (LinkageError e) {
      fail(NT_APPENDER_CLASS + " attempted to load its native library: " + e);
    }
  }

  /**
   * A properties configuration naming the appender must not trigger the
   * native library load nor attach the appender.
   */
  public void testPropertyConfiguratorCannotInstantiateNTEventLogAppender() {
    Properties props = new Properties();
    props.put("log4j.rootLogger", "DEBUG, NT");
    props.put("log4j.appender.NT", NT_APPENDER_CLASS);
    props.put("log4j.appender.NT.Source", "Log4j");
    try {
      PropertyConfigurator.configure(props);
    } catch (LinkageError e) {
      fail(NT_APPENDER_CLASS + " attempted to load its native library: " + e);
    }
    Logger root = Logger.getRootLogger();
    assertNull(root.getAppender("NT"));
    assertFalse(hasAppenders(root));
  }

  /**
   * An XML configuration naming the appender must not trigger the
   * native library load nor attach the appender.
   */
  public void testDOMConfiguratorCannotInstantiateNTEventLogAppender() {
    String xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
        + "<!DOCTYPE log4j:configuration SYSTEM \"log4j.dtd\">\n"
        + "<log4j:configuration xmlns:log4j=\"http://jakarta.apache.org/log4j/\">\n"
        + "  <appender name=\"NT\" class=\"" + NT_APPENDER_CLASS + "\">\n"
        + "    <param name=\"Source\" value=\"Log4j\"/>\n"
        + "  </appender>\n"
        + "  <root>\n"
        + "    <priority value=\"debug\"/>\n"
        + "    <appender-ref ref=\"NT\"/>\n"
        + "  </root>\n"
        + "</log4j:configuration>\n";
    try {
      new DOMConfigurator().doConfigure(new StringReader(xml),
              LogManager.getLoggerRepository());
    } catch (LinkageError e) {
      fail(NT_APPENDER_CLASS + " attempted to load its native library: " + e);
    }
    Logger root = Logger.getRootLogger();
    assertNull(root.getAppender("NT"));
    assertFalse(hasAppenders(root));
  }

  private static boolean hasAppenders(final Logger logger) {
    Enumeration appenders = logger.getAllAppenders();
    return appenders != null && appenders.hasMoreElements();
  }
}

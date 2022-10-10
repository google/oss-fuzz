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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Log4jSlf4jFuzzer {
  public Log4jSlf4jFuzzer(FuzzedDataProvider data) {
  }

  void runTest(FuzzedDataProvider data) {
    Logger logger = LoggerFactory.getLogger(Log4jSlf4jFuzzer.class);

    logger.isDebugEnabled();
    logger.isErrorEnabled();
    logger.isInfoEnabled();
    logger.isTraceEnabled();
    logger.isWarnEnabled();
    logger.debug(data.consumeString(10));
    logger.error(data.consumeString(10));
    logger.info(data.consumeString(10));
    logger.warn(data.consumeString(10));
    logger.debug(data.consumeString(10), new NullPointerException());
    logger.error(data.consumeString(10), new NullPointerException());
    logger.info(data.consumeString(10), new NullPointerException());
    logger.warn(data.consumeString(10), new NullPointerException());
  }

  public static void fuzzerInitialize() {

    System.setProperty("log4j.debug", "");
    org.apache.log4j.BasicConfigurator.configure();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Log4jSlf4jFuzzer testClosure = new Log4jSlf4jFuzzer(data);
    testClosure.runTest(data);
  }
}

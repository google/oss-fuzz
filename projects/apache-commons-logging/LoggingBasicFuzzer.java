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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class LoggingBasicFuzzer {
	public LoggingBasicFuzzer(FuzzedDataProvider data) {
	}
	
	void runTest(FuzzedDataProvider data) {
		Log logger = LogFactory.getLog(LoggingBasicFuzzer.class);

		logger.isDebugEnabled();
		logger.isErrorEnabled();
		logger.isFatalEnabled();
		logger.isInfoEnabled();
		logger.isTraceEnabled();
		logger.isWarnEnabled();
		logger.debug(data.consumeString(10));
		logger.error(data.consumeString(10));
		logger.fatal(data.consumeString(10));
		logger.info(data.consumeString(10));
		logger.warn(data.consumeString(10));
		logger.debug(data.consumeString(10), new NullPointerException());
		logger.error(data.consumeString(10), new NullPointerException());
		logger.fatal(data.consumeString(10), new NullPointerException());
		logger.info(data.consumeString(10), new NullPointerException());
		logger.warn(data.consumeString(10), new NullPointerException());
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		LoggingBasicFuzzer testClosure = new LoggingBasicFuzzer(data);
		testClosure.runTest(data);
	}
}

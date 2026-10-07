// Copyright 2023 Google LLC
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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.jboss.logging.*;
import java.util.Properties;


class LoggingFuzzer {
    private static final Logger LOGGER = Logger.getLogger(LoggingFuzzer.class);
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        String[] logManagers = { "jboss","jdk","log4j2","log4j","slf4j"};
        String logManager = data.pickValue(logManagers);
        Properties props = System.getProperties();
        props.setProperty("org.jboss.logging.provider", logManager);
        int i1 = data.consumeInt();
        int i2 = data.consumeInt();
        String s2 = data.consumeString(10);
        String s1 = data.consumeRemainingAsString();
        LOGGER.debugf(s1,i1,i2,s2);
        LOGGER.tracef(s1,i1,i2,s2);
        LOGGER.errorf(s1,i1,i2,s2);
        
    }
}

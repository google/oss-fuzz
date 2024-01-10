// Copyright 2024 Google LLC
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

import org.apache.zookeeper.server.util.*;
import java.io.*;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
public class MessageTrackerPeekReceivedFuzzer {
    private static final Logger LOG = LoggerFactory.getLogger(MessageTrackerPeekReceivedFuzzer.class);
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        System.setProperty(MessageTracker.MESSAGE_TRACKER_ENABLED, "true");
        long timestamp1 = data.consumeLong();
        MessageTracker messageTracker = new MessageTracker(data.consumeInt(1, 100));
        String sid = data.consumeRemainingAsString();
        messageTracker.dumpToLog(sid);
        messageTracker.peekSent();
        messageTracker.peekReceived();
        messageTracker.trackSent(timestamp1);
        messageTracker.peekSentTimestamp();
        messageTracker.peekReceived();
        messageTracker.dumpToLog(sid);
        messageTracker.peekSent();
        messageTracker.peekReceived();
        messageTracker.trackSent(timestamp1);
        messageTracker.trackReceived(timestamp1);
        messageTracker.peekSentTimestamp();
        messageTracker.peekReceivedTimestamp();
        messageTracker.dumpToLog(sid);
        messageTracker.peekSent();
        messageTracker.peekReceived();
        System.clearProperty(MessageTracker.MESSAGE_TRACKER_ENABLED);
    }
}
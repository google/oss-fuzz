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
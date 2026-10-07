import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.netflix.servo.monitor.*;
import com.netflix.servo.tag.BasicTagList;
import com.netflix.servo.tag.SortedTagList;
import com.netflix.servo.tag.TagList;

public class MonitorConfigFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String key = data.consumeString(500);
        String value = data.consumeString(500);
        String name = data.consumeRemainingAsString();
        if (key.isEmpty() || value.isEmpty()) {
            return;
        }

        TagList tags1 = new BasicTagList(SortedTagList.builder()
            .withTag(key, value)
            .build());
        
        MonitorConfig m = new MonitorConfig.Builder(name).withTags(tags1).build();
        m.getName();
        m.getTags();
        m.hashCode();
        m.getPublishingPolicy();

        new BasicCounter(m);
	}
}
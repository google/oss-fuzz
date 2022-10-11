package org.springframework.cloud.netflix.eureka.config;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.ArrayList;
import java.util.List;
import org.springframework.cloud.netflix.eureka.config.HostnameBasedUrlRandomizer;
public class HostnameBasedUrlRandomizerFuzzer {

    FuzzedDataProvider dataProvider;

    public HostnameBasedUrlRandomizerFuzzer(FuzzedDataProvider dataProvider) {
        this.dataProvider = dataProvider;
    }

    public String getString() {
        return dataProvider.consumeString(16);
    }

    public ArrayList<String> getStringArrayList() {
        ArrayList<String> list = new ArrayList<String>();
        int n = dataProvider.consumeInt(0, 10);
        for (int i = 0; i < n; ++i) {
            list.add(getString());
        }
        return list;
    }

    void test() {
        HostnameBasedUrlRandomizer randomizer = new HostnameBasedUrlRandomizer(getString());
        randomizer.randomize(getStringArrayList());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider dataProvider) {
        HostnameBasedUrlRandomizerFuzzer closure = new HostnameBasedUrlRandomizerFuzzer(dataProvider);
        closure.test();
    }
}
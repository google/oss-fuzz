import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.netflix.config.*;

import java.util.*;

public class DynamicPropertyFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		String property = data.consumeString(50);
		String value = data.consumeString(100);

		DynamicLongProperty dpLong =  new DynamicLongProperty(property, data.consumeLong());
		dpLong.get();

		DynamicFloatProperty dpFloat = new DynamicFloatProperty(property, data.consumeFloat());
		dpFloat.get();

		DynamicStringProperty dpString = new DynamicStringProperty(property, value);
		dpString.get();

		DynamicStringSetProperty dpStringSet = new DynamicStringSetProperty(property, value);
		dpStringSet.get();

		DynamicStringMapProperty dpStringMap = new DynamicStringMapProperty(property, value);
		dpStringMap.get();

		DynamicStringListProperty dpStringList = new DynamicStringListProperty(property, value);
		dpStringList.get();

		DynamicContextualProperty dpContextual = new DynamicContextualProperty<Object>(property, value);
	} 
}
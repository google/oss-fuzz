import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.hibernate.validator.internal.util.ReflectionHelper;

import java.util.ArrayList;
import java.util.List;

public class GetIndexedValueFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        List<Object> list = new ArrayList<Object>();
		for(int i = 0; i < data.consumeInt(1,10); i++)
		    list.add( data.consumeString(10) );

		Object value = ReflectionHelper.getIndexedValue( list, data.consumeInt(1,10) );
    }
}
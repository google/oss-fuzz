package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import io.reactivex.rxjava3.core.*;
import java.util.ArrayList;

public class ObservableFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        
        ArrayList<Integer> arrayList = new ArrayList();
        int n = data.consumeInt(1, 100);
        for (int i = 0; i <= n; i++) {
            arrayList.add(data.consumeInt());
        }

        Observable<Integer> items = Observable.fromIterable(arrayList);
        IntegerObserver observer = new IntegerObserver();

        items.subscribe(observer);
        if (!observer.getArrayList().equals(arrayList)) {
            throw new FuzzerSecurityIssueLow("Data Loss");
        }
    }
}

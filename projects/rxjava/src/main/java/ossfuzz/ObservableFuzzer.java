/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
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

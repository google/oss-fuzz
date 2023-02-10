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

import java.util.ArrayList;

import io.reactivex.rxjava3.core.Observer;
import io.reactivex.rxjava3.disposables.Disposable;

public class IntegerObserver implements io.reactivex.rxjava3.core.Observer<Integer> {
    ArrayList<Integer> m_ArrayList;

    public IntegerObserver() {
        m_ArrayList = new ArrayList<Integer>();
    }

    public void onComplete() {
    }

    public void onError(Throwable e) {
    }

    public void onNext(Integer t) {
        m_ArrayList.add(t);
    }

    public void onSubscribe(Disposable d) {
    }

    public ArrayList<Integer> getArrayList() {
        return m_ArrayList;
    }
}

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

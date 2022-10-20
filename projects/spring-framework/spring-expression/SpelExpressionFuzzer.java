// Copyright 2022 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.util.*;

public class SpelExpressionFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ExpressionParser parser = new SpelExpressionParser();

        // Create and fill a dummy object with fuzzer data
        String[] strArr = new String[data.consumeInt(0, 50)];
        for (int i = 0; i < strArr.length; i++) {
            strArr[i] = data.consumeString(100);
        }

        DummyClass dummyObject = new DummyClass();
        dummyObject._char = data.consumeChar();
        dummyObject._string = data.consumeString(100);
        dummyObject._boolArray = data.consumeBooleans(50);
        dummyObject._double = data.consumeDouble();
        dummyObject._intArray = data.consumeInts(50);
        dummyObject._long = data.consumeLong();
        dummyObject._byteArray = data.consumeBytes(50);
        dummyObject._boolean = data.consumeBoolean();
        dummyObject._byte = data.consumeByte();
        dummyObject._stringArray = strArr;
        dummyObject._int = data.consumeInt();
        dummyObject._short = data.consumeShort();
        dummyObject._float = data.consumeFloat();
        dummyObject._arrayList = Arrays.asList(strArr);

        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setRootObject(dummyObject);

        try {
            Expression expr = parser.parseExpression(data.consumeRemainingAsString());
            expr.getValue();
            expr.getValue(dummyObject);
        } catch (SpelEvaluationException | SpelParseException ignored) {}
    }

    public static class DummyClass {
        public TreeMap<String, Integer> _treeMap;
        public List<String> _arrayList;
        public Set<String> _hashSet;
        public Map<String, Object> _hashMap;
        public List<Integer> _asList = Arrays.asList(1, 2, 3);
        public int[] _intArray;
        public long[] _longArray;
        public short[] _shortArray;
        public float[] _floatArray;
        public double[] _doubleArray;
        public byte[] _byteArray;
        public char[] _charArray;
        public boolean[] _boolArray;
        public String[] _stringArray;
        public BitSet _bitSet;
        public Date _date;
        public TimeZone _timeZone;
        public Calendar _calendar;
        public Locale _locale;
        public Integer[] _integerArray;
        public boolean _boolean;
        public char _char;
        public byte _byte;
        public short _short;
        public int _int;
        public float _float;
        public Long _long;
        public Double _double;
        public String _string;
    }
}

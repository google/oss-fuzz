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
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.lang.IllegalArgumentException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

public class ReadTreeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ObjectMapper mapper = new ObjectMapper();

        try {
            JsonNode root = mapper.readTree(data.consumeString(1000000));
            int target = data.consumeInt();
            switch(target%3) {
                case 0:
                    String rootValue = data.consumeString(10000);
                    if (root.get(rootValue) != null ) {
                        String rootGet = root.get(rootValue).asText();
                    }
                case 1:
                    String json = mapper.writeValueAsString(root);
                case 2:
                    String treeAt = data.consumeString(100000);
                    JsonNode node = root.at(treeAt);
                    DummyClass dc = mapper.treeToValue(node, DummyClass.class);
                }
        } catch (JsonProcessingException | IllegalArgumentException e) { }
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
    }
}
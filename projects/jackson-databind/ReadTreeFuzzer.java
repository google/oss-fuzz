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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;

import java.util.*;
import java.math.BigInteger;
import java.math.BigDecimal;
import java.lang.IllegalArgumentException;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.core.JacksonException;

public class ReadTreeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ObjectMapper mapper = new ObjectMapper();

        try {
            JsonNode root = mapper.readTree(data.consumeString(500000));
            if (root == null) return;
            
            // Test various JsonNode operations
            int numOperations = data.consumeInt(1, 20);
            for (int i = 0; i < numOperations && data.remainingBytes() > 10; i++) {
                int operation = data.consumeInt(0, 25);
                switch(operation) {
                    case 0:
                        // get by field name
                        String fieldName = data.consumeString(100);
                        JsonNode child = root.get(fieldName);
                        if (child != null) {
                            child.asText();
                            child.isNull();
                            child.isValueNode();
                        }
                        break;
                    case 1:
                        // get by index
                        int idx = data.consumeInt();
                        root.get(idx);
                        break;
                    case 2:
                        // path operations
                        String path = data.consumeString(200);
                        JsonNode pathNode = root.path(path);
                        pathNode.isMissingNode();
                        break;
                    case 3:
                        // at (JsonPointer)
                        String pointer = data.consumeString(200);
                        root.at(pointer);
                        break;
                    case 4:
                        // type checks
                        root.isArray();
                        root.isObject();
                        root.isTextual();
                        root.isNumber();
                        root.isBoolean();
                        root.isBinary();
                        root.isPojo();
                        root.isIntegralNumber();
                        root.isFloatingPointNumber();
                        root.isBigDecimal();
                        root.isBigInteger();
                        break;
                    case 5:
                        // value extraction
                        root.asText();
                        root.asText("default");
                        break;
                    case 6:
                        root.asInt();
                        root.asInt(0);
                        break;
                    case 7:
                        root.asLong();
                        root.asLong(0L);
                        break;
                    case 8:
                        root.asDouble();
                        root.asDouble(0.0);
                        break;
                    case 9:
                        root.asBoolean();
                        root.asBoolean(false);
                        break;
                    case 10:
                        // tree traversal - Jackson 3.x uses values() and properties()
                        root.values();
                        root.properties();
                        root.iterator();
                        break;
                    case 11:
                        // has operations
                        String checkField = data.consumeString(100);
                        root.has(checkField);
                        root.has(data.consumeInt());
                        root.hasNonNull(checkField);
                        break;
                    case 12:
                        // size
                        root.size();
                        root.isEmpty();
                        break;
                    case 13:
                        // find operations
                        String findField = data.consumeString(100);
                        root.findValue(findField);
                        root.findPath(findField);
                        root.findValues(findField);
                        root.findValuesAsString(findField);
                        root.findParent(findField);
                        root.findParents(findField);
                        break;
                    case 14:
                        // withObject operations (for ObjectNode)
                        if (root.isObject()) {
                            try {
                                String withField = data.consumeString(100);
                                root.withObject(withField);
                            } catch (UnsupportedOperationException e) {}
                        }
                        break;
                    case 15:
                        // withArray (for ObjectNode)
                        if (root.isObject()) {
                            try {
                                String arrayField = data.consumeString(100);
                                root.withArray(arrayField);
                            } catch (UnsupportedOperationException e) {}
                        }
                        break;
                    case 16:
                        // equals
                        String json2 = data.consumeString(10000);
                        try {
                            JsonNode other = mapper.readTree(json2);
                            root.equals(other);
                        } catch (JacksonException e) {}
                        break;
                    case 17:
                        // treeToValue
                        int classIdx = data.consumeInt(0, classes.length - 1);
                        mapper.treeToValue(root, classes[classIdx]);
                        break;
                    case 18:
                        // write operations
                        mapper.writeValueAsString(root);
                        break;
                    case 19:
                        mapper.writeValueAsBytes(root);
                        break;
                    case 20:
                        // deepCopy
                        root.deepCopy();
                        break;
                    case 21:
                        // number operations if applicable
                        if (root.isNumber()) {
                            root.numberValue();
                            root.canConvertToInt();
                            root.canConvertToLong();
                            root.canConvertToExactIntegral();
                        }
                        break;
                    case 22:
                        // binary operations if applicable
                        if (root.isBinary()) {
                            root.binaryValue();
                        }
                        break;
                    case 23:
                        // textValue
                        root.textValue();
                        break;
                    case 24:
                        // pretty print
                        root.toPrettyString();
                        break;
                    case 25:
                        // require operations
                        try {
                            root.require();
                            root.requireNonNull();
                        } catch (IllegalArgumentException e) {}
                        break;
                }
            }
        } catch (JacksonException | IllegalArgumentException e) { }
    }
    
    public static Class[] classes = { DummyClass.class, Integer.class, String.class, Byte.class, List.class, Map.class,
        TreeMap.class, BitSet.class, TimeZone.class, Date.class, Calendar.class, Locale.class };

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

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

import java.util.*;
import java.io.Reader;
import java.io.StringReader;
import java.io.IOException;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.File;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonFactory;

public class ObjectReader2Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        boolean doThis;
        byte[] fileData;
        int fuzzInt1, fuzzInt2;
        FileOutputStream out;
        Object o;
        Reader stringR;
        ObjectReader r, r2, r3;
        JsonParser jp;

        DeserializationFeature[] deserializationfeatures = new DeserializationFeature[]{DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS,
                                        DeserializationFeature.USE_BIG_INTEGER_FOR_INTS,
                                        DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY,
                                        DeserializationFeature.READ_ENUMS_USING_TO_STRING,
                                        DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
                                        DeserializationFeature.UNWRAP_ROOT_VALUE,
                                        DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS,
                                        DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT,
                                        DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT,
                                        DeserializationFeature.ACCEPT_FLOAT_AS_INT,
                                        DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE,
                                        DeserializationFeature.READ_DATE_TIMESTAMPS_AS_NANOSECONDS,
                                        DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL,
                                        DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE,
                                        DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,
                                        DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                                        DeserializationFeature.FAIL_ON_INVALID_SUBTYPE,
                                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                                        DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS,
                                        DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY,
                                        DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS,
                                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES,
                                        DeserializationFeature.WRAP_EXCEPTIONS,
                                        DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                                        DeserializationFeature.EAGER_DESERIALIZER_FETCH};

        ObjectMapper mapper = new ObjectMapper();
        int idx = data.consumeInt(0, classes.length - 1);
        r = mapper.readerFor(classes[idx]);

        // set reader settings
        for (int i = 0; i < deserializationfeatures.length; i++) {
            if (data.consumeBoolean()) {
                r = r.with(deserializationfeatures[i]);
            } else {
                r = r.without(deserializationfeatures[i]);
            }
        }

        try {
            // Select a method and call it
            int callType = data.consumeInt();
            switch (callType%19) {
            case 0:
                r.readValue(data.consumeRemainingAsString());
            case 1:
                r.readValue(data.consumeRemainingAsBytes());
            case 2:
                r.readTree(data.consumeRemainingAsString());
            case 3:
                r.readTree(data.consumeRemainingAsBytes());
            case 4:
                doThis = data.consumeBoolean();
                jp = r.createParser(data.consumeRemainingAsBytes());
                o = r.readValue(jp);
                if (doThis) {
                    r3 = r.withValueToUpdate(o);
                }
            case 5:
                stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                r.readValue(stringR);
            case 6:
                stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                r.readValues(stringR);
            case 7:
                r.readValues(data.consumeRemainingAsString());
            case 8:
                r.readValue(data.consumeRemainingAsBytes());
            case 9:
                doThis = data.consumeBoolean();
                jp = r.createParser(data.consumeRemainingAsBytes());
                o = r.readValues(jp);
                if (doThis) {
                    r3 = r.withValueToUpdate(o);
                }
            case 10:
                doThis = data.consumeBoolean();
                jp = r.createParser(data.consumeRemainingAsBytes());
                o = r.readTree(jp);
                if (doThis) {
                    r3 = r.withValueToUpdate(o);
                }
            case 11:
                stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                r.readTree(stringR);
            case 12:
                fileData = data.consumeRemainingAsBytes();
                out = new FileOutputStream("fuzzFile");
                out.write(fileData);
                out.close();
                r.readValue(new File("fuzzFile"));
            case 13:
                fileData = data.consumeRemainingAsBytes();
                out = new FileOutputStream("fuzzFile");
                out.write(fileData);
                out.close();
                r.readValues(new File("fuzzFile"));
            case 14:
                fileData = data.consumeRemainingAsBytes();
                out = new FileOutputStream("fuzzFile");
                out.write(fileData);
                out.close();
                jp = r.createParser(new File("fuzzFile"));
                o = r.readTree(jp);
            case 15:
                fuzzInt1 = data.consumeInt();
                fuzzInt2 = data.consumeInt();
                r.readValue(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
            case 16:
                fuzzInt1 = data.consumeInt();
                fuzzInt2 = data.consumeInt();
                r.readValues(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
            case 17:
                fuzzInt1 = data.consumeInt();
                fuzzInt2 = data.consumeInt();
                r.readTree(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
            case 18:
                fuzzInt1 = data.consumeInt();
                fuzzInt2 = data.consumeInt();
                jp = r.createParser(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
            }
            
            // target with();
            if (data.consumeBoolean()) {
                JsonFactory jf = new JsonFactory();
                r2 = r.with(jf);                
            }
        } catch (IOException e) { }

        try {
            Files.delete(Paths.get("fuzzFile"));
        } catch (IOException e) { }
    }

    public static Class[] classes = { DummyClass.class, Integer.class, String.class, Byte.class, List.class, Map.class,
        TreeMap.class, BitSet.class, TimeZone.class, Date.class, Calendar.class, Locale.class, Long.class };

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
        public Long _long;
        public Double _double;
    }
}

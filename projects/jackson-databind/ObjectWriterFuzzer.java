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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.core.JsonProcessingException;

public class ObjectWriterFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        MapperFeature[] mapperfeatures = new MapperFeature[]{MapperFeature.AUTO_DETECT_CREATORS,
                                        MapperFeature.AUTO_DETECT_FIELDS,
                                        MapperFeature.AUTO_DETECT_GETTERS,
                                        MapperFeature.AUTO_DETECT_IS_GETTERS,
                                        MapperFeature.AUTO_DETECT_SETTERS,
                                        MapperFeature.REQUIRE_SETTERS_FOR_GETTERS,
                                        MapperFeature.USE_GETTERS_AS_SETTERS,
                                        MapperFeature.INFER_CREATOR_FROM_CONSTRUCTOR_PROPERTIES,
                                        MapperFeature.INFER_PROPERTY_MUTATORS,
                                        MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS,
                                        MapperFeature.ALLOW_VOID_VALUED_PROPERTIES,
                                        MapperFeature.CAN_OVERRIDE_ACCESS_MODIFIERS,
                                        MapperFeature.OVERRIDE_PUBLIC_ACCESS_MODIFIERS,
                                        MapperFeature.SORT_PROPERTIES_ALPHABETICALLY,
                                        MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_VALUES,
                                        MapperFeature.ALLOW_EXPLICIT_PROPERTY_RENAMING,
                                        MapperFeature.USE_STD_BEAN_NAMING,
                                        MapperFeature.ALLOW_COERCION_OF_SCALARS,
                                        MapperFeature.DEFAULT_VIEW_INCLUSION,
                                        MapperFeature.IGNORE_DUPLICATE_MODULE_REGISTRATIONS,
                                        MapperFeature.IGNORE_MERGE_FOR_UNMERGEABLE,
                                        MapperFeature.USE_BASE_TYPE_AS_DEFAULT_IMPL,
                                        MapperFeature.USE_STATIC_TYPING,
                                        MapperFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES};

        SerializationFeature[] serializationfeatures = new SerializationFeature[]{SerializationFeature.INDENT_OUTPUT,
                                        SerializationFeature.CLOSE_CLOSEABLE,
                                        SerializationFeature.WRAP_ROOT_VALUE,
                                        SerializationFeature.WRITE_DATE_KEYS_AS_TIMESTAMPS,
                                        SerializationFeature.WRITE_CHAR_ARRAYS_AS_JSON_ARRAYS,
                                        SerializationFeature.WRITE_ENUMS_USING_TO_STRING,
                                        SerializationFeature.WRITE_ENUMS_USING_INDEX,
                                        SerializationFeature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED,
                                        SerializationFeature.WRITE_BIGDECIMAL_AS_PLAIN,
                                        SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS,
                                        SerializationFeature.USE_EQUALITY_FOR_OBJECT_ID,
                                        SerializationFeature.FAIL_ON_EMPTY_BEANS,
                                        SerializationFeature.WRAP_EXCEPTIONS,
                                        SerializationFeature.FLUSH_AFTER_WRITE_VALUE,
                                        SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                                        SerializationFeature.WRITE_NULL_MAP_VALUES,
                                        SerializationFeature.WRITE_EMPTY_JSON_ARRAYS,
                                        SerializationFeature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS,
                                        SerializationFeature.EAGER_SERIALIZER_FETCH};

        ObjectMapper mapper = new ObjectMapper();

        for (int i = 0; i < mapperfeatures.length; i++) {
            if (data.consumeBoolean()) {
                mapper.enable(mapperfeatures[i]);
            } else {
                mapper.disable(mapperfeatures[i]);
            }
        }

        for (int i = 0; i < serializationfeatures.length; i++) {
            if (data.consumeBoolean()) {
                mapper.enable(serializationfeatures[i]);
            } else {
                mapper.disable(serializationfeatures[i]);
            }
        }

        try {
            DummyClass dc = mapper.readValue(data.consumeRemainingAsString(), DummyClass.class);
            byte[] jb = mapper.writeValueAsBytes(dc);
        } catch (JsonProcessingException e) { }
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
        public Long _long;
        public Double _double;
    }
}

// Copyright 2023 Google LLC
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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import com.esotericsoftware.yamlbeans.YamlException;
import com.esotericsoftware.yamlbeans.YamlReader;
import com.esotericsoftware.yamlbeans.YamlWriter;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;


class YamlWriterFuzzer {
    static int cn = 29;

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        int dummyNum = data.consumeInt(0, 2^cn - 1);
        DummyClass dummyClass = getDummyClass(data, dummyNum);

        YamlWriter writer = null;
        try {
            writer = new YamlWriter(new FileWriter("output.yaml"));
        } catch (IOException e) {
            return;
        }

        try {
            writer.write(dummyClass);
            writer.close();
        } catch (YamlException e) {
        }

        YamlReader reader = null;
        try {
            reader = new YamlReader(new FileReader("output.yaml"));

            while (true) {
                Object object = null;
                object = reader.read(DummyClass.class);

                if (object == null) break;
            }
        } catch (FileNotFoundException | YamlException e) {
        } catch (NoSuchElementException | NullPointerException | IndexOutOfBoundsException e) {
            // Need to catch to let fuzzer continue.
        }
    }

    public static DummyClass getDummyClass (FuzzedDataProvider data, int dummyNum) {
        DummyClass dummyClass = new DummyClass();

        for (int bit = 0; bit < cn; ++bit) {
            if (((dummyNum >> bit) & 1) == 1) {
                switch (bit) {
                    case 0:
                        for (int i = 0; i < data.consumeInt(0, 50); i++) {
                            try {
                                dummyClass._treeMap.put(data.consumeString(50), data.consumeInt());
                            } catch (NullPointerException e) {
                            }
                        }
                        break;
                    case 1:
                        for (int i = 0; i < data.consumeInt(0, 50); i++) {
                            try {
                                dummyClass._arrayList.add(data.consumeString(50));
                            } catch (NullPointerException e) {
                            }
                        }
                        break;
                    case 2:
                        for (int i = 0; i < data.consumeInt(0, 50); i++) {
                            try {
                                dummyClass._hashSet.add(data.consumeString(50));
                            } catch (NullPointerException e) {
                            }
                        }
                        break;
                    case 3:
                        for (int i = 0; i < data.consumeInt(0, 50); i++) {
                            try {
                                dummyClass._hashMap.put(data.consumeString(50), data.consumeString(50));
                            } catch (NullPointerException e) {
                            }
                        }
                        break;
                    case 4:
                        Integer[] integerArr = new Integer[data.consumeInt(0, 50)];
                        for (int i = 0; i < integerArr.length; i++) {
                            integerArr[i] = data.consumeInt();
                        }
                        dummyClass._asList = Arrays.asList(integerArr);
                        break;
                    case 5:
                        dummyClass._intArray = data.consumeInts(50);
                        break;
                    case 6:
                        dummyClass._longArray = data.consumeLongs(50);
                        break;
                    case 7:
                        dummyClass._shortArray = data.consumeShorts(50);
                        break;
                    case 8:
                        float[] floatArr = new float[data.consumeInt(0, 50)];
                        for (int i = 0; i < floatArr.length; i++) {
                            floatArr[i] = data.consumeFloat();
                        }
                        dummyClass._floatArray = floatArr;
                        break;
                    case 9:
                        double[] doubleArr = new double[data.consumeInt(0, 50)];
                        for (int i = 0; i < doubleArr.length; i++) {
                            doubleArr[i] = data.consumeDouble();
                        }
                        dummyClass._doubleArray = doubleArr;
                        break;
                    case 10:
                        dummyClass._byteArray = data.consumeBytes(50);
                        break;
                    case 11:
                        char[] charArr = new char[data.consumeInt(0, 50)];
                        for (int i = 0; i < charArr.length; i++) {
                            charArr[i] = data.consumeChar();
                        }
                        dummyClass._charArray = charArr;
                        break;
                    case 12:
                        dummyClass._boolArray = data.consumeBooleans(50);
                        break;
                    case 13:
                        String[] strArr = new String[data.consumeInt(0, 50)];
                        for (int i = 0; i < strArr.length; i++) {
                            strArr[i] = data.consumeString(50);
                        }
                        dummyClass._stringArray = strArr;
                        break;
                    case 14:
                        BitSet bitSet = BitSet.valueOf(data.consumeLongs(50));
                        dummyClass._bitSet = bitSet;
                        break;
                    case 15:
                        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        try {
                            dummyClass._date = dateFormat.parse(data.consumeString(50));
                        } catch (ParseException e) {
                        }
                        break;
                    case 16:
                        TimeZone tz = TimeZone.getTimeZone(data.consumeString(50));
                        dummyClass._timeZone = tz;
                        break;
                    case 17:
                        Calendar calendar = new GregorianCalendar(data.consumeInt(),data.consumeInt(),data.consumeInt());
                        dummyClass._calendar = calendar;
                        break;
                    case 18:
                        Locale locale = new Locale(data.consumeString(50));
                        dummyClass._locale = locale;
                        break;
                    case 19:
                        Integer[] integerArr2 = new Integer[data.consumeInt(0, 50)];
                        for (int i = 0; i < integerArr2.length; i++) {
                            integerArr2[i] = data.consumeInt();
                        }
                        dummyClass._integerArray = integerArr2;
                        break;
                    case 20:
                        dummyClass._boolean = data.consumeBoolean();
                        break;
                    case 21:
                        dummyClass._char = data.consumeChar();
                        break;
                    case 22:
                        dummyClass._byte = data.consumeByte();
                        break;
                    case 23:
                        dummyClass._short = data.consumeShort();
                        break;
                    case 24:
                        dummyClass._int = data.consumeInt();
                        break;
                    case 25:
                        dummyClass._float = data.consumeFloat();
                        break;
                    case 26:
                        dummyClass._long = data.consumeLong();
                        break;
                    case 27:
                        dummyClass._double = data.consumeDouble();
                        break;
                    case 28:
                        dummyClass._string = data.consumeString(50);
                        break;
                }
            }
        }
        return dummyClass;
    }

    public static class DummyClass implements Serializable {
        public TreeMap<String, Integer> _treeMap;
        public List<String> _arrayList;
        public Set<String> _hashSet;
        public Map<String, Object> _hashMap;
        public List<Integer> _asList;
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
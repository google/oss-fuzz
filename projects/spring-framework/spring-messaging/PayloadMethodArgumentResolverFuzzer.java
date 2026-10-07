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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import org.springframework.core.annotation.SynthesizingMethodParameter;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.converter.MarshallingMessageConverter;
import org.springframework.messaging.converter.StringMessageConverter;
import org.springframework.messaging.handler.annotation.support.MethodArgumentNotValidException;
import org.springframework.messaging.handler.annotation.support.PayloadMethodArgumentResolver;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.util.MimeType;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class PayloadMethodArgumentResolverFuzzer {
    public static Class<?>[] classes = { DummyClass.class, Integer.class, String.class, Byte.class, List.class, Map.class,
            TreeMap.class, BitSet.class, TimeZone.class, Date.class, Calendar.class, Locale.class };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String payload = data.consumeString(200);
        String headerName = data.consumeString(50);
        String headerValue = data.consumeString(50);

        Validator validator = new Validator() {
            @Override
            public boolean supports(Class<?> clazz) {
                return true;
            }

            @Override
            public void validate(Object target, Errors errors) {}
        };

        PayloadMethodArgumentResolver resolver = new PayloadMethodArgumentResolver(new StringMessageConverter(), validator);

        Method method;
        SynthesizingMethodParameter parameter;
        Message<String> message;
        try {
            method = (data.pickValue(classes)).getDeclaredMethod("foo", data.consumeBoolean() ? data.pickValue(classes) : null);
            parameter = new SynthesizingMethodParameter(method, data.consumeInt(0, 100));
            message = MessageBuilder.withPayload(payload)
                    .setHeader(headerName, headerValue)
                    .build();
            message.getHeaders().get(headerName, data.pickValue(classes));
        } catch (NoSuchMethodException | IllegalArgumentException ignored) {
            return;
        }

        try {
            Object result = resolver.resolveArgument(parameter, message);
            if (!Objects.equals(result, payload)) {
                throw new FuzzerSecurityIssueLow("Payload is different");
            }
        } catch (MethodArgumentNotValidException ignored) {
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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

        public void foo(String dummy) {}
    }
}
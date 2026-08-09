// Copyright 2021 Google LLC
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

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.KryoException;
import com.esotericsoftware.kryo.serializers.CompatibleFieldSerializer;

public class DeserializeStringFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Kryo kryo = new Kryo();
        kryo.register(SomeClass.class);

        kryo.setReferences(data.consumeBoolean());
        if (data.consumeBoolean())
            kryo.setDefaultSerializer(CompatibleFieldSerializer.class);

        Input in = new Input(data.consumeRemainingAsBytes());
        try {
            kryo.readObject(in, SomeClass.class);
        } catch (KryoException e) {
        } finally {
            in.close();
        }
    }

    public static final class SomeClass {
        String value;
    }
}

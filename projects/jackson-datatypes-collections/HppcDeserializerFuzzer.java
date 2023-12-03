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
///////////////////////////////////////////////////////////////////////////
import com.carrotsearch.hppc.IntArrayDeque;
import com.carrotsearch.hppc.IntArrayList;
import com.carrotsearch.hppc.IntDeque;
import com.carrotsearch.hppc.IntHashSet;
import com.carrotsearch.hppc.IntIndexedContainer;
import com.carrotsearch.hppc.IntSet;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.hppc.HppcModule;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** This fuzzer targets the deserialization methods of hppc object */
public class HppcDeserializerFuzzer {
  private static ObjectMapper mapper;
  private static List<Class> choice;

  public static void fuzzerInitialize() {
    // Register the Hppc for the deserialization
    mapper = new ObjectMapper().registerModule(new HppcModule());
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the deserialize methods for different eclipse collections object
      Class type = data.pickValue(choice);
      String value = data.consumeRemainingAsString();
      mapper.readValue(value, type);
    } catch (IOException e) {
      // Known exception
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<Class>();
    choice.add(IntArrayDeque.class);
    choice.add(IntArrayList.class);
    choice.add(IntDeque.class);
    choice.add(IntHashSet.class);
    choice.add(IntIndexedContainer.class);
    choice.add(IntSet.class);
  }
}

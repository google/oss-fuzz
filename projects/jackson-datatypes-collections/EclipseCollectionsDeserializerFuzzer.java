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
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.eclipsecollections.EclipseCollectionsModule;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** This fuzzer targets the deserialization methods of eclipse collections object */
public class EclipseCollectionsDeserializerFuzzer {
  private static ObjectMapper mapper;
  private static List<Class> choice;

  public static void fuzzerInitialize() {
    // Register the EclipseCollectionsModule for the deserialization
    mapper = new ObjectMapper().registerModule(new EclipseCollectionsModule());
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the deserialize methods for different eclipse collections object
      Class type = data.pickValue(choice);
      String value = data.consumeRemainingAsString();
      mapper.readValue(value, type);
      mapper.readTree(value);
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }

  private static void initializeClassChoice() {
    final String[] types = {"Boolean", "Byte", "Char", "Double", "Float", "Int", "Long", "Short"};

    choice = new ArrayList<Class>();
    for (String key : types) {
      addClass("org.eclipse.collections.api.bag.primitive." + key + "Bag");
      addClass("org.eclipse.collections.api.collection.primitive." + key + "Collection");
      addClass("org.eclipse.collections.api.list.primitive." + key + "List");
      addClass("org.eclipse.collections.api.set.primitive." + key + "Set");
      for (String value : types) {
        addClass("org.eclipse.collections.api.tuple.primitive." + key + value + "Pair");
        if (!key.equals("Boolean")) {
          addClass("org.eclipse.collections.api.map.primitive.Mutable" + key + value + "Map");
          addClass("org.eclipse.collections.api.map.primitive.Immutable" + key + value + "Map");
          addClass("org.eclipse.collections.api.map.primitive." + key + value + "Map");
        }
      }
    }
  }

  private static void addClass(String name) {
    try {
      choice.add(Class.forName(name));
    } catch (ClassNotFoundException e) {
      // Skip missing classes
    }
  }
}

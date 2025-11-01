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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.pcollections.PCollectionsModule;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.pcollections.ConsPStack;
import org.pcollections.HashPMap;
import org.pcollections.MapPBag;
import org.pcollections.MapPSet;
import org.pcollections.OrderedPSet;
import org.pcollections.PBag;
import org.pcollections.PCollection;
import org.pcollections.PMap;
import org.pcollections.PSequence;
import org.pcollections.PSet;
import org.pcollections.PStack;
import org.pcollections.PVector;
import org.pcollections.TreePVector;

/** This fuzzer targets the methods of PCollections object */
public class PCollectionsFuzzer {
  private static ObjectMapper mapper;
  private static List<TypeReference> choice;

  public static void fuzzerInitialize() {
    // Register the PCollectionsModule for fuzzing
    mapper = new ObjectMapper().registerModule(new PCollectionsModule());
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the methods for different PCollections objects
      TypeReference type = data.pickValue(choice);
      String value = data.consumeRemainingAsString();
      mapper.readValue(value, type);
    } catch (IOException e) {
      // Known exception
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<TypeReference>();

    choice.add(new TypeReference<ConsPStack<Integer>>() {});
    choice.add(new TypeReference<HashPMap<String, Integer>>() {});
    choice.add(new TypeReference<MapPBag<Integer>>() {});
    choice.add(new TypeReference<MapPSet<Integer>>() {});
    choice.add(new TypeReference<OrderedPSet<Integer>>() {});
    choice.add(new TypeReference<PBag<Integer>>() {});
    choice.add(new TypeReference<PCollection<Integer>>() {});
    choice.add(new TypeReference<PMap<String, Integer>>() {});
    choice.add(new TypeReference<PSequence<Integer>>() {});
    choice.add(new TypeReference<PSet<Integer>>() {});
    choice.add(new TypeReference<PStack<Integer>>() {});
    choice.add(new TypeReference<PVector<Integer>>() {});
    choice.add(new TypeReference<TreePVector<Integer>>() {});
  }
}

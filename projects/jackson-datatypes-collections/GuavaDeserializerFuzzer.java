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
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.google.common.cache.Cache;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableMultiset;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.ImmutableSortedMultiset;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.LinkedHashMultiset;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multiset;
import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;
import com.google.common.collect.SortedMultiset;
import com.google.common.collect.TreeMultimap;
import com.google.common.collect.TreeMultiset;
import com.google.common.hash.HashCode;
import com.google.common.net.HostAndPort;
import com.google.common.net.InternetDomainName;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** This fuzzer targets the deserialization methods of Guava object */
public class GuavaDeserializerFuzzer {
  private static ObjectMapper mapper;
  private static List<TypeReference> choice;

  public static void fuzzerInitialize() {
    // Register the GuavaModule for the deserialization
    GuavaModule module = new GuavaModule();
    module.configureAbsentsAsNulls(false);
    mapper = new ObjectMapper().registerModule(module);
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the deserialization methods for different Guava objects
      TypeReference type = data.pickValue(choice);
      String value = data.consumeRemainingAsString();
      mapper.readValue(value, type);
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<TypeReference>();

    choice.add(new TypeReference<Cache<String, String>>() {});
    choice.add(new TypeReference<ImmutableListContainer>() {});
    choice.add(new TypeReference<ImmutableMapContainer>() {});
    choice.add(new TypeReference<HashCode>() {});
    choice.add(new TypeReference<HostAndPort>() {});
    choice.add(new TypeReference<ArrayListMultimapContainer>() {});
    choice.add(new TypeReference<Range>() {});
    choice.add(new TypeReference<InternetDomainName>() {});
    choice.add(new TypeReference<ImmutableSet<Integer>>() {});
    choice.add(new TypeReference<ImmutableSet<String>>() {});
    choice.add(new TypeReference<ImmutableList<Integer>>() {});
    choice.add(new TypeReference<ImmutableList<String>>() {});
    choice.add(new TypeReference<ImmutableSortedSet<Integer>>() {});
    choice.add(new TypeReference<ImmutableSortedSet<String>>() {});
    choice.add(new TypeReference<ImmutableMap<String, String>>() {});
    choice.add(new TypeReference<ImmutableSortedMap<String, String>>() {});
    choice.add(new TypeReference<ImmutableBiMap<String, String>>() {});
    choice.add(new TypeReference<ArrayListMultimap<String, String>>() {});
    choice.add(new TypeReference<TreeMultimap<String, String>>() {});
    choice.add(new TypeReference<Multimap<String, String>>() {});
    choice.add(new TypeReference<HashMultimap<String, String>>() {});
    choice.add(new TypeReference<ImmutableMultimap<String, String>>() {});
    choice.add(new TypeReference<Multiset<String>>() {});
    choice.add(new TypeReference<SortedMultiset<String>>() {});
    choice.add(new TypeReference<LinkedHashMultiset<String>>() {});
    choice.add(new TypeReference<HashMultiset<String>>() {});
    choice.add(new TypeReference<TreeMultiset<String>>() {});
    choice.add(new TypeReference<ImmutableMultiset<String>>() {});
    choice.add(new TypeReference<ImmutableSortedMultiset<String>>() {});
    choice.add(new TypeReference<RangeSet>() {});
  }

  public static class ImmutableListContainer {
    public ImmutableList<ImmutableList<String>> lists = ImmutableList.of();
  }

  private static class ImmutableMapContainer {
    public ImmutableMap<String, ImmutableMap<String, String>> maps = ImmutableMap.of();
  }

  private static class ArrayListMultimapContainer {
    @JsonTypeInfo(include = JsonTypeInfo.As.PROPERTY, use = JsonTypeInfo.Id.CLASS)
    public Object object;
  }
}

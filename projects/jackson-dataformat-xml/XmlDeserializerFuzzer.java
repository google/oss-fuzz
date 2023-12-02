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
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.dataformat.xml.JacksonXmlModule;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/** This fuzzer targets the deserialization methods of Xml objects */
public class XmlDeserializerFuzzer {
  private static XmlMapper mapper;
  private static List<Class> choice;

  public static void fuzzerInitialize() {
    // Register the XmlModule for the deserialization
    mapper = new XmlMapper(new JacksonXmlModule());
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the deserialize methods for different xml objects
      Class type = data.pickValue(choice);
      String value = data.consumeRemainingAsString();
      mapper.readValue(value, type);
    } catch (IOException e) {
      // Known exception
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<Class>();
    choice.add(ByteArrayContainer.class);
    choice.add(ByteArrayOutputStream.class);
    choice.add(Byte[].class);
    choice.add(ModelContainer.class);
    choice.add(DelegateContainer.class);
    choice.add(RawContainer.class);
    choice.add(MapContainer.class);
    choice.add(ListContainer.class);
    choice.add(ArrayContainer.class);
    choice.add(EnumFuzz.class);
    choice.add(EnumContainer.class);
    choice.add(Exception.class);
    choice.add(Map.class);
    choice.add(List.class);
    choice.add(Set.class);
    choice.add(Stream.class);
    choice.add(String.class);
    choice.add(Boolean.class);
    choice.add(Character.class);
    choice.add(Byte.class);
    choice.add(Integer.class);
    choice.add(Long.class);
    choice.add(Short.class);
    choice.add(Double.class);
    choice.add(Float.class);
    choice.add(BigInteger.class);
    choice.add(BigDecimal.class);
    choice.add(Number.class);
  }

  private static class ByteArrayContainer {
    public byte[] value;

    public ByteArrayContainer(byte[] value) {
      this.value = value;
    }
  }

  @JsonRootName("Model")
  private static class ModelContainer {
    @JacksonXmlProperty(isAttribute = true, localName = "string")
    public String string;

    @JsonCreator
    public ModelContainer(@JsonProperty(value = "string", required = true) String string) {
      this.string = string;
    }
  }

  private static class DelegateContainer {
    public String string;

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public DelegateContainer(String string) {
      this.string = string;
    }
  }

  @JsonPropertyOrder({"id", "raw"})
  private static class RawContainer {
    @JsonRawValue public String string;
  }

  private static class MapContainer {
    public Map<Integer, String> map;

    public void setMap(Map<Integer, String> map) {
      this.map = map;
    }
  }

  private static class ListContainer {
    public List<String> list;

    public void setList(List<String> list) {
      this.list = list;
    }
  }

  private static class ArrayContainer {
    public String[] array;

    public String[] getArray() {
      return array;
    }

    public void setArray(String[] array) {
      this.array = array;
    }
  }

  private static enum EnumFuzz {
    A,
    B,
    C,
    D,
    E;
  }

  private static class EnumContainer {
    public EnumFuzz enumFuzz;

    public EnumContainer(EnumFuzz enumFuzz) {
      this.enumFuzz = enumFuzz;
    }
  }
}

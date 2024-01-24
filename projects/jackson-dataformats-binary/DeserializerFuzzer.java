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
import com.amazon.ion.IonException;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.avro.AvroFactory;
import com.fasterxml.jackson.dataformat.avro.AvroFactoryBuilder;
import com.fasterxml.jackson.dataformat.avro.AvroMapper;
import com.fasterxml.jackson.dataformat.avro.AvroParser;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.fasterxml.jackson.dataformat.ion.IonFactory;
import com.fasterxml.jackson.dataformat.ion.IonFactoryBuilder;
import com.fasterxml.jackson.dataformat.ion.IonObjectMapper;
import com.fasterxml.jackson.dataformat.ion.IonParser;
import com.fasterxml.jackson.dataformat.protobuf.ProtobufFactory;
import com.fasterxml.jackson.dataformat.protobuf.ProtobufMapper;
import com.fasterxml.jackson.dataformat.smile.SmileFactory;
import com.fasterxml.jackson.dataformat.smile.SmileParser;
import com.fasterxml.jackson.dataformat.smile.databind.SmileMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

/** This fuzzer targets the deserialization methods of Avro/Cbor/Ion/Protobuf/Smile objects */
public class DeserializerFuzzer {
  private static ObjectMapper mapper;
  private static List<Class> choice;

  public static void fuzzerInitialize() {
    mapper = null;
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonParser parser = null;

    try {
      // Initialize ObjectMapper object
      switch (data.consumeInt(1, 5)) {
        case 1:
          AvroFactoryBuilder avroFactoryBuilder;
          if (data.consumeBoolean()) {
            avroFactoryBuilder = AvroFactory.builderWithApacheDecoder();
          } else {
            avroFactoryBuilder = AvroFactory.builderWithNativeDecoder();
          }

          mapper =
              AvroMapper.builder(
                      avroFactoryBuilder
                          .enable(data.pickValue(EnumSet.allOf(AvroParser.Feature.class)))
                          .build())
                  .build();
          break;
        case 2:
          mapper =
              CBORMapper.builder(
                      CBORFactory.builder()
                          .enable(data.pickValue(EnumSet.allOf(CBORGenerator.Feature.class)))
                          .build())
                  .build();
          break;
        case 3:
          IonFactoryBuilder ionFactoryBuilder;
          if (data.consumeBoolean()) {
            ionFactoryBuilder = IonFactory.builderForBinaryWriters();
          } else {
            ionFactoryBuilder = IonFactory.builderForTextualWriters();
          }

          mapper =
              IonObjectMapper.builder(
                      ionFactoryBuilder
                          .enable(data.pickValue(EnumSet.allOf(IonParser.Feature.class)))
                          .build())
                  .build();
          break;
        case 4:
          mapper = ProtobufMapper.builder(ProtobufFactory.builder().build()).build();
          break;
        case 5:
          mapper =
              SmileMapper.builder(
                      SmileFactory.builder()
                          .enable(data.pickValue(EnumSet.allOf(SmileParser.Feature.class)))
                          .build())
                  .build();
          break;
      }

      // Failsafe logic
      if (mapper == null) {
        return;
      }

      // Fuzz the deserialize methods for different Avro/Cbor/Ion/Protobuf/Smile objects
      if (data.consumeBoolean()) {
        byte[] output = data.consumeRemainingAsBytes();
        parser = mapper.getFactory().createParser(new ByteArrayInputStream(output));
        mapper.readTree(parser);
      } else {
        Class type = data.pickValue(choice);
        String value = data.consumeRemainingAsString();
        if ((value == null) || (value.isEmpty())) {
          return;
        }
        mapper.readValue(value, type);
        if (mapper instanceof AvroMapper) {
          mapper.readerFor(type).with(((AvroMapper) mapper).schemaFrom(value)).readValue(value);
        }
      }
    } catch (IOException
        | IllegalArgumentException
        | UnsupportedOperationException
        | IonException e) {
      // Known exception
    } finally {
      try {
        if (parser != null) {
          parser.close();
        }
      } catch (IOException e) {
        // Ignore exceptions for closing JsonParser object
      }
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<Class>();
    choice.add(ByteArrayContainer.class);
    choice.add(ByteArrayOutputStream.class);
    choice.add(ModelContainer.class);
    choice.add(DelegateContainer.class);
    choice.add(RawContainer.class);
    choice.add(MapContainer.class);
    choice.add(ListContainer.class);
    choice.add(ArrayContainer.class);
    choice.add(UUIDContainer.class);
    choice.add(EnumFuzz.class);
    choice.add(EnumContainer.class);
    choice.add(Exception.class);
    choice.add(Error.class);
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
    choice.add(String.class);
    choice.add(Character[].class);
    choice.add(Date.class);
  }

  private static class ByteArrayContainer {
    public byte[] value;

    public ByteArrayContainer(byte[] value) {
      this.value = value;
    }
  }

  @JsonRootName("Model")
  private static class ModelContainer {
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

  private static class UUIDContainer {
    public UUID uuid;

    public UUIDContainer(UUID uuid) {
      this.uuid = uuid;
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

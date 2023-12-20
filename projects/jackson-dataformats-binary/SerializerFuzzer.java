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
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.FormatFeature;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** This fuzzer targets the serialization methods of Avro/Cbor/Ion/Protobuf/Smile objects */
public class SerializerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JsonFactory factory = null;
    JsonGenerator generator = null;
    ObjectMapper mapper = null;
    FormatFeature feature = null;

    try {
      switch (data.consumeInt(1, 5)) {
        case 1:
          // Initialize AvroFactoryBuilder object
          AvroFactoryBuilder avroFactoryBuilder;
          if (data.consumeBoolean()) {
            avroFactoryBuilder = AvroFactory.builderWithApacheDecoder();
          } else {
            avroFactoryBuilder = AvroFactory.builderWithNativeDecoder();
          }

          // Initialize AvroFactory object
          factory = avroFactoryBuilder.build();

          // Initialize AvroMapper object
          mapper = AvroMapper.builder((AvroFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(AvroParser.Feature.class));
          break;
        case 2:
          // Initialize CBORFactory object
          factory = CBORFactory.builder().build();

          // Initialize CBORMapper object
          mapper = CBORMapper.builder((CBORFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(CBORGenerator.Feature.class));
          break;
        case 3:
          // Initialize IonFactoryBuilder object
          IonFactoryBuilder ionFactoryBuilder;
          if (data.consumeBoolean()) {
            ionFactoryBuilder = IonFactory.builderForBinaryWriters();
          } else {
            ionFactoryBuilder = IonFactory.builderForTextualWriters();
          }

          // Initialize IonFactory object
          factory = ionFactoryBuilder.build();

          // Initialize IonObjectMapper object
          mapper = IonObjectMapper.builder((IonFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(IonParser.Feature.class));
          break;
        case 4:
          // Initialize ProtobufFactory object
          factory = ProtobufFactory.builder().build();

          // Initialize ProtobufMapper object
          mapper = ProtobufMapper.builder((ProtobufFactory) factory).build();
          break;
        case 5:
          // Initialize SmileFactory object
          factory = SmileFactory.builder().build();

          // Initialize SmileMapper object
          mapper = SmileMapper.builder((SmileFactory) factory).build();

          // Initialize format options
          feature = data.pickValue(EnumSet.allOf(SmileParser.Feature.class));
          break;
      }

      // Failsafe logic
      if ((factory == null) || (mapper == null)) {
        return;
      }

      // Initialize ObjectWriter object
      ObjectWriter writer = mapper.writer();

      // Initialize ObjectNode object
      ObjectNode node = mapper.createObjectNode();

      // Randomize writer options
      if (data.consumeBoolean()) {
        writer = writer.withDefaultPrettyPrinter();
      }
      if (feature != null) {
        writer = writer.with(feature);
      }

      // Object to write
      Object object = null;

      // Fuzz the serialize methods for different XML objects
      switch (data.consumeInt(1, 28)) {
        case 1:
          node.put("data", data.consumeRemainingAsBytes());
          object = node;
          break;
        case 2:
          generator = factory.createGenerator(new StringWriter());
          generator.writeStartObject();
          generator.writeBinaryField("data", data.consumeRemainingAsBytes());
          generator.writeEndObject();
          break;
        case 3:
          generator = factory.createGenerator(new StringWriter());
          generator.writeStartObject();
          generator.writeString(data.consumeRemainingAsString());
          generator.writeEndObject();
          break;
        case 4:
          Map<String, String> innerMap =
              Collections.singletonMap("inner_data", data.consumeRemainingAsString());
          Map<String, Map<String, String>> map = Collections.singletonMap("data", innerMap);
          object = map;
          break;
        case 5:
          List<String> innerList = Collections.singletonList(data.consumeRemainingAsString());
          List<List<String>> list = Collections.singletonList(innerList);
          object = list;
          break;
        case 6:
          object = BigInteger.valueOf(data.consumeLong());
          break;
        case 7:
          object = data.consumeRemainingAsString();
          break;
        case 8:
          object = data.consumeRemainingAsBytes();
          break;
        case 9:
          object = BigDecimal.valueOf(data.consumeDouble());
          break;
        case 10:
          object = data.consumeBoolean();
          break;
        case 11:
          object = data.consumeInt();
          break;
        case 12:
          object = data.consumeLong();
          break;
        case 13:
          object = data.consumeDouble();
          break;
        case 14:
          object = data.consumeBoolean();
          break;
        case 15:
          object = data.consumeByte();
          break;
        case 16:
          object = data.consumeChar();
          break;
        case 17:
          object = data.consumeBoolean();
          break;
        case 18:
          object = new ByteArrayInputStream(data.consumeRemainingAsBytes());
          break;
        case 19:
          object = new RawContainer(data.consumeRemainingAsString());
          break;
        case 20:
          object = new ByteBufferContainer(data.consumeRemainingAsBytes());
          break;
        case 21:
          object = new MapContainer(data.consumeRemainingAsString());
          break;
        case 22:
          object = new ListContainer(data.consumeRemainingAsString());
          break;
        case 23:
          object = new ByteArrayContainer(data.consumeRemainingAsBytes());
          break;
        case 24:
          object = new UUID(data.consumeLong(), data.consumeLong());
          break;
        case 25:
          object = new UUIDContainer(data.consumeLong(), data.consumeLong());
          break;
        case 26:
          object = new ArrayContainer(data.consumeRemainingAsString());
          break;
        case 27:
          object = new Date(data.consumeLong());
          break;
        case 28:
          object = data.consumeRemainingAsString().toCharArray();
          break;
      }

      writer.writeValueAsString(object);
      writer.writeValueAsBytes(object);
    } catch (IOException
        | IllegalArgumentException
        | UnsupportedOperationException
        | IonException e) {
      // Known exception
    } finally {
      try {
        if (generator != null) {
          // Close JsonGenerator object
          generator.flush();
          generator.close();
        }
      } catch (IOException e) {
        // Ignore exceptions for generator closing
      }
    }
  }

  @JsonRootName("ByteArray")
  private static class ByteArrayContainer {
    public byte[] value;

    public ByteArrayContainer(byte[] value) {
      this.value = value;
    }
  }

  @JsonPropertyOrder({"id", "raw"})
  private static class RawContainer {
    @JsonRawValue public String string;
    @JsonRawValue public char[] charArray;

    public RawContainer(String string) {
      this.string = string;
      this.charArray = string.toCharArray();
    }
  }

  private static class ByteBufferContainer {
    public ByteBuffer byteBuffer;

    public ByteBufferContainer(byte[] byteArray) {
      this.byteBuffer = ByteBuffer.allocateDirect(byteArray.length);
      this.byteBuffer.put(byteArray);
    }
  }

  private static class MapContainer {
    public Map<Integer, String> map;

    public MapContainer(String string) {
      this.map = new HashMap<Integer, String>();
      this.map.put(0, string);
    }
  }

  private static class ListContainer {
    public List<String> list;

    public ListContainer(String string) {
      this.list = new ArrayList<String>();
      this.list.add(string);
    }
  }

  private static class ArrayContainer {
    public char[] array;

    public ArrayContainer(String string) {
      this.array = string.toCharArray();
    }

    public void setArray(char[] array) {
      this.array = array;
    }
  }

  private static class UUIDContainer {
    public UUID uuid;

    public UUIDContainer(long a, long b) {
      this.uuid = new UUID(a, b);
    }
  }
}

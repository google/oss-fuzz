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
import org.locationtech.spatial4j.context.SpatialContext;
import org.locationtech.spatial4j.context.SpatialContextFactory;
import org.locationtech.spatial4j.exception.InvalidShapeException;
import org.locationtech.spatial4j.shape.Shape;
import java.text.ParseException;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [org.locationtech.spatial4j.context.SpatialContext] public org.locationtech.spatial4j.shape.Shape readShapeFromWkt(java.lang.String) throws org.locationtech.spatial4j.exception.InvalidShapeException,java.text.ParseException
public class SpatialContextFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      SpatialContext obj = new SpatialContext(new SpatialContextFactory());
      obj.readShapeFromWkt(data.consumeRemainingAsString());
    } catch (InvalidShapeException | ParseException | AssertionError e) {
      // Known exception
    }
  }
}

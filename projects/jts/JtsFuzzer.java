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
import org.locationtech.jts.geom.Geometry;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.geom.PrecisionModel;
import org.locationtech.jts.io.ParseException;
import org.locationtech.jts.io.WKTReader;
import org.locationtech.jts.util.AssertionFailedException;

public class JtsFuzzer {
  private static PrecisionModel.Type[] types = {
      PrecisionModel.FIXED, PrecisionModel.FLOATING, PrecisionModel.FLOATING_SINGLE};

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int[] choices = data.consumeInts(data.consumeInt(1, 10));
      GeometryFactory factory = new GeometryFactory(new PrecisionModel(data.pickValue(types)));
      WKTReader reader = new WKTReader(factory);
      Geometry g1 = reader.read(data.consumeString(data.remainingBytes() / 2));
      Geometry g2 = reader.read(data.consumeRemainingAsString());

      for (Integer choice : choices) {
        switch (choice % 16) {
          case 0:
            g1.equalsNorm(g2);
            break;
          case 1:
            g1.distance(g2);
            break;
          case 2:
            g1.disjoint(g2);
            break;
          case 3:
            g1.touches(g2);
            break;
          case 4:
            g1.intersects(g2);
            break;
          case 5:
            g1.crosses(g2);
            break;
          case 6:
            g1.within(g2);
            break;
          case 7:
            g1.contains(g2);
            break;
          case 8:
            g1.overlaps(g2);
            break;
          case 9:
            g1.covers(g2);
            break;
          case 10:
            g1.coveredBy(g2);
            break;
          case 11:
            g1.relate(g2);
            break;
          case 12:
            g1.intersection(g2);
            break;
          case 13:
            g1.union(g2);
            break;
          case 14:
            g1.difference(g2);
            break;
          case 15:
            g1.symDifference(g2);
            break;
        }
      }
    } catch (ParseException | AssertionFailedException | IllegalArgumentException e) {
      // Known exception
    }
  }
}

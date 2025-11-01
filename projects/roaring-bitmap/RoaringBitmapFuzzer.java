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
import org.roaringbitmap.longlong.Roaring64Bitmap;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [org.roaringbitmap.longlong.Roaring64Bitmap] public static org.roaringbitmap.longlong.Roaring64Bitmap bitmapOf(long[])
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [org.roaringbitmap.longlong.Roaring64Bitmap] public void and(org.roaringbitmap.longlong.Roaring64Bitmap)
// Target method: [org.roaringbitmap.longlong.Roaring64Bitmap] public void or(org.roaringbitmap.longlong.Roaring64Bitmap)
// Target method: [org.roaringbitmap.longlong.Roaring64Bitmap] public void xor(org.roaringbitmap.longlong.Roaring64Bitmap)
public class RoaringBitmapFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Roaring64Bitmap bitmap1 = Roaring64Bitmap.bitmapOf(data.consumeLongs(data.consumeInt(1, 10)));
    Roaring64Bitmap bitmap2 = Roaring64Bitmap.bitmapOf(data.consumeLongs(data.consumeInt(1, 10)));

    switch (data.consumeInt(1, 3)) {
      case 1:
        bitmap1.and(bitmap2);
        break;
      case 2:
        bitmap1.or(bitmap2);
        break;
      case 3:
        bitmap1.xor(bitmap2);
        break;
    }
  }
}

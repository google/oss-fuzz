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
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.xerial.snappy.Snappy;
import org.xerial.snappy.BitShuffle;
import java.io.IOException;
import java.util.Arrays;


public class BitShuffleFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    int SIZE = 4096;
    fuzz_bitshuffle_ints(data.consumeInts(SIZE));
    fuzz_bitshuffle_longs(data.consumeLongs(SIZE));
    fuzz_bitshuffle_shorts(data.consumeShorts(SIZE));
  }

  static void fuzz_bitshuffle_ints(int[] original){
    int[] result;

    try{   
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      result = BitShuffle.unshuffleIntArray(uncompressed);
    }
    catch( IOException e ){
      return;
    }
    
    if(Arrays.equals(original,result) == false)
    {
      throw new IllegalStateException("Original and uncompressed data are different");
    }

  }//fuzz_bitshuffle_ints

  static void fuzz_bitshuffle_longs(long[] original){
    long[] result;

    try{   
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      result = BitShuffle.unshuffleLongArray(uncompressed);
    }
    catch( IOException e ){
      return;
    }
    
    if(Arrays.equals(original,result) == false)
    {
      throw new IllegalStateException("Original and uncompressed data are different");
    }

  }//fuzz_bitshuffle_longs

  static void fuzz_bitshuffle_shorts(short[] original){
    short[] result;

    try{   
      byte[] shuffledByteArray = BitShuffle.shuffle(original);
      byte[] compressed = Snappy.compress(shuffledByteArray);
      byte[] uncompressed = Snappy.uncompress(compressed);
      result = BitShuffle.unshuffleShortArray(uncompressed);
    }
    catch( IOException e ){
      return;
    }
    
    if(Arrays.equals(original,result) == false)
    {
      throw new IllegalStateException("Original and uncompressed data are different");
    }

  }//fuzz_bitshuffle_shorts  

}


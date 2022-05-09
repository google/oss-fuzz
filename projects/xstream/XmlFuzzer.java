
// Copyright 2022 Google LLC
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

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.StaxDriver;

import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.mapper.CannotResolveClassException;
import com.thoughtworks.xstream.converters.ConversionException;

class FuzzObj {
  private String string1;
  
  public FuzzObj(String s1){
    this.string1 = s1;  
  }
}

public class XmlFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    XStream xstream;
		switch(data.consumeInt(1,3)){
			case 1: xstream = new XStream(new DomDriver());
			break;
   		case 2: xstream = new XStream(new StaxDriver());
			break;
      case 3: xstream = new XStream();
      break;
			default: return;
		}
    try{
      FuzzObj fo = (FuzzObj) xstream.fromXML(data.consumeRemainingAsString());
    }
    catch (StreamException | CannotResolveClassException | ConversionException e){
      return;
    }
  }
}

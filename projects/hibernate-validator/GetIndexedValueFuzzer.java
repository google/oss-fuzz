// Copyright 2024 Google LLC
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
import org.hibernate.validator.internal.util.ReflectionHelper;

import java.util.ArrayList;
import java.util.List;

public class GetIndexedValueFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        List<Object> list = new ArrayList<Object>();
		for(int i = 0; i < data.consumeInt(1,10); i++)
		    list.add( data.consumeString(10) );

		Object value = ReflectionHelper.getIndexedValue( list, data.consumeInt(1,10) );
    }
}
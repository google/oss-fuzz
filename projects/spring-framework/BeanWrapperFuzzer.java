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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.InvalidPropertyException;
import java.util.List;
import java.util.Map;

public class BeanWrapperFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		String property = data.consumeString(100);
		Bean bean = new Bean();
		BeanWrapper bw = new BeanWrapperImpl(bean);
		try {
			bw.setPropertyValue(property, data.consumeRemainingAsString());
			bw.getPropertyType(property);
		} catch (ConversionNotSupportedException | InvalidPropertyException ignored) {}
	}

	public static class Bean {

		private String prop;

		private Bean nested;

		private Bean[] array;

		private Bean[][] multiArray;

		private Bean[][][] threeDimensionalArray;

		private List<Bean> list;

		private List<List<Bean>> multiList;

		private List listNotParameterized;

		private Map<String, Bean> map;

		public String getProp() {
			return prop;
		}

		public void setProp(String prop) {
			this.prop = prop;
		}

		public Bean getNested() {
			return nested;
		}

		public void setNested(Bean nested) {
			this.nested = nested;
		}

		public Bean[] getArray() {
			return array;
		}

		public void setArray(Bean[] array) {
			this.array = array;
		}

		public Bean[][] getMultiArray() {
			return multiArray;
		}

		public void setMultiArray(Bean[][] multiArray) {
			this.multiArray = multiArray;
		}

		public Bean[][][] getThreeDimensionalArray() {
			return threeDimensionalArray;
		}

		public void setThreeDimensionalArray(Bean[][][] threeDimensionalArray) {
			this.threeDimensionalArray = threeDimensionalArray;
		}

		public List<Bean> getList() {
			return list;
		}

		public void setList(List<Bean> list) {
			this.list = list;
		}

		public List<List<Bean>> getMultiList() {
			return multiList;
		}

		public void setMultiList(List<List<Bean>> multiList) {
			this.multiList = multiList;
		}

		public List getListNotParameterized() {
			return listNotParameterized;
		}

		public void setListNotParameterized(List listNotParameterized) {
			this.listNotParameterized = listNotParameterized;
		}

		public Map<String, Bean> getMap() {
			return map;
		}

		public void setMap(Map<String, Bean> map) {
			this.map = map;
		}
	}
}

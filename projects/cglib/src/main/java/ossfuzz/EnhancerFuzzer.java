/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.lang.reflect.Method;
import net.sf.cglib.proxy.Enhancer;
import net.sf.cglib.proxy.FixedValue;
import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;

class SampleClass {

	String test() {
		return "Hello World";
	}

	String test(String string) {
		return string;
	}
};

class FixedValueCallback implements FixedValue {
	FixedValueCallback(String string) {
		m_string = string;
	}

	@Override
	public Object loadObject() throws Exception {
		return m_string;
	}

	public String getString() {
		return m_string;
	}

	protected String m_string;
}

class MethodInterceptorCallback implements MethodInterceptor {

	MethodInterceptorCallback(String string) {
		m_string = string;
	}

	@Override
	public Object intercept(Object obj, Method method, Object[] args, MethodProxy proxy) throws Throwable {
		if (method.getDeclaringClass() == SampleClass.class) {
			if (method.getParameterCount() == 0) {
				return m_string;
			}
		}
		
		return proxy.invokeSuper(obj, args);
	}

	public String getString() {
		return m_string;
	}

	protected String m_string;
}

public class EnhancerFuzzer {

	public static void fixedValueCallback(FuzzedDataProvider fuzzedDataProvider) {
		Enhancer enhancer = new Enhancer();
		enhancer.setSuperclass(SampleClass.class);

		FixedValueCallback fixedValueCallback = new FixedValueCallback(fuzzedDataProvider.consumeRemainingAsString());
		enhancer.setCallback(fixedValueCallback);
  
		SampleClass proxy = (SampleClass) enhancer.create();
		if (!proxy.test().equals(fixedValueCallback.getString())) {
			throw new FuzzerSecurityIssueLow("FixedValue defect");
		}
		if (!proxy.test("someString").equals(fixedValueCallback.getString())) {
			throw new FuzzerSecurityIssueLow("FixedValue defect");
		}
	}

	public static void methodInterceptorCallback(FuzzedDataProvider fuzzedDataProvider) {
		
		Enhancer enhancer = new Enhancer();
		enhancer.setSuperclass(SampleClass.class);

		MethodInterceptorCallback methodInterceptorCallback = new MethodInterceptorCallback(fuzzedDataProvider.consumeString(5));
		enhancer.setCallback(methodInterceptorCallback);
  
		SampleClass proxy = (SampleClass) enhancer.create();
		if (!proxy.test().equals(methodInterceptorCallback.getString())) {
			throw new FuzzerSecurityIssueLow("MethodInterceptor defect");
		}

		String argument = fuzzedDataProvider.consumeRemainingAsString();
		if (!proxy.test(argument).equals(argument)) {
			throw new FuzzerSecurityIssueLow("MethodInterceptor defect");
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		fixedValueCallback(fuzzedDataProvider);
		methodInterceptorCallback(fuzzedDataProvider);
	}
}
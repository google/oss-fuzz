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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import org.springframework.transaction.interceptor.TransactionAttribute;
import org.springframework.transaction.interceptor.TransactionAttributeEditor;
import org.springframework.transaction.interceptor.TransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionAttributeSourceEditor;

public class TransactionAttributeSourceEditorFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		String source = data.consumeRemainingAsString();

		TransactionAttributeSourceEditor editor = new TransactionAttributeSourceEditor();
		try {
			editor.setAsText(source);
		} catch (IllegalArgumentException e) {}

		TransactionAttributeSource tas = (TransactionAttributeSource) editor.getValue();
		if (tas == null) {
			return;
		}

		TransactionAttribute ta = null;
		try {
			ta = tas.getTransactionAttribute(Object.class.getMethod("dummyMethod"), null);
		} catch (NoSuchMethodException e) {}

		if (ta == null) {
			return;
		}
		ta.getPropagationBehavior();
		ta.rollbackOn(new RuntimeException());
	}
}
